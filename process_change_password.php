<?php
require_once 'config.php'; // Carrega configurações LDAP, funções e session_start()

// Redireciona se o usuário não estiver logado
if (!isset($_SESSION['username']) || !isset($_SESSION['user_dn'])) {
    header("Location: index.php?message=" . urlencode("Sessão inválida ou usuário não encontrado. Por favor, faça login novamente."));
    exit;
}

$currentUserDN = $_SESSION['user_dn'];
$currentUsername = $_SESSION['username'];
$currentPassword = $_POST['current_password'] ?? ''; // Senha atual do formulário (pode estar vazia para primeiro acesso)
$newPassword = $_POST['new_password'] ?? '';
$confirmPassword = $_POST['confirm_password'] ?? '';
$currentPasswordSkipped = isset($_POST['current_password_skipped']) && $_POST['current_password_skipped'] === 'true';

$redirect_to_change_password_error = "Location: change_password.php?error=";
$redirect_to_index_success = "Location: index.php?success_message=";

// 1. Validação PHP (reforçando a validação do JS)
if (empty($newPassword) || empty($confirmPassword)) {
    header($redirect_to_change_password_error . urlencode("Nova senha e confirmação são obrigatórias."));
    exit;
}
if ($newPassword !== $confirmPassword) {
    header($redirect_to_change_password_error . urlencode("As novas senhas não coincidem."));
    exit;
}
if (!preg_match(PASSWORD_POLICY_REGEX, $newPassword)) {
    $policyError = "A nova senha não atende aos requisitos: Mínimo 14 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais.";
    header($redirect_to_change_password_error . urlencode($policyError));
    exit;
}

// 2. Conectar ao LDAP para verificar o status do usuário (pwdLastSet)
$ldap_conn_check_user = ldap_connect_admin(); // Conecta como admin para ler atributos do usuário
if (!$ldap_conn_check_user) {
    error_log("PROCESS_PWCH: Falha ao conectar como admin para verificar pwdLastSet do usuario: " . ldap_error(null)); // Passar null para erro geral
    header($redirect_to_change_password_error . urlencode("Erro interno ao verificar seu status. Contate o suporte."));
    exit;
}

$filter_user_dn = "(distinguishedName=" . ldap_escape($currentUserDN, "", LDAP_ESCAPE_FILTER) . ")";
$attrs_user_check = ["pwdlastset", "useraccountcontrol"];
$search_user_check = @ldap_read($ldap_conn_check_user, $currentUserDN, $filter_user_dn, $attrs_user_check);

if (!$search_user_check) {
    error_log("PROCESS_PWCH: Falha na busca de atributos do usuario ($currentUserDN) para verificar pwdLastSet: " . ldap_error($ldap_conn_check_user));
    @ldap_close($ldap_conn_check_user);
    header($redirect_to_change_password_error . urlencode("Não foi possível verificar seu status no AD. Contate o suporte."));
    exit;
}

$entries_user_check = @ldap_get_entries($ldap_conn_check_user, $search_user_check);
@ldap_close($ldap_conn_check_user); // Fechar conexão admin após a leitura

if (!$entries_user_check || $entries_user_check['count'] == 0) {
    error_log("PROCESS_PWCH: Usuario ($currentUserDN) nao encontrado no AD para verificar pwdLastSet.");
    header($redirect_to_change_password_error . urlencode("Sua conta não foi encontrada no Active Directory. Contate o suporte."));
    exit;
}

$pwdLastSet = $entries_user_check[0]['pwdlastset'][0];
$is_first_login_or_reset = ($pwdLastSet == "0");

// 3. Determinar o contexto de bind para a operação de alteração de senha
$bind_dn_for_modify = '';
$bind_password_for_modify = '';
$current_password_required = true; // Sinaliza se a senha atual precisa ser validada

if ($is_first_login_or_reset) {
    // Cenário de primeiro acesso ou senha resetada: Bind com credenciais de admin
    $bind_dn_for_modify = LDAP_ADMIN_DN;
    $bind_password_for_modify = LDAP_ADMIN_PASSWORD;
    $current_password_required = false; // Nao exige senha atual
    error_log("PROCESS_PWCH: Cenário de 'primeiro acesso/reset' detectado (pwdLastSet=0). Tentando bind com ADMIN_DN.");
} else {
    // Cenário de troca de senha normal: Bind com credenciais do próprio usuário
    $bind_dn_for_modify = $currentUserDN;
    $bind_password_for_modify = $currentPassword;
    $current_password_required = true; // Exige senha atual
    error_log("PROCESS_PWCH: Cenário de 'troca de senha própria'. Tentando bind com USER_DN.");
}

// Se a senha atual for obrigatória e não foi fornecida
if ($current_password_required && empty($currentPassword)) {
    header($redirect_to_change_password_error . urlencode("A senha atual é obrigatória para alterar sua senha."));
    exit;
}

// 4. Conectar ao LDAP para realizar a modificação
$ldap_conn_modify = null;
$ldap_port_modify = defined('LDAP_PORT') ? LDAP_PORT : 636; // Usa 636 como padrão para LDAPS

// Tentar primário
$ldap_conn_modify = @ldap_connect(LDAP_SERVER, $ldap_port_modify);
// Se primário falhar e backup estiver definido, tentar backup
if (!$ldap_conn_modify && defined('LDAP_SERVER_BACKUP') && LDAP_SERVER_BACKUP) {
    $ldap_conn_modify = @ldap_connect(LDAP_SERVER_BACKUP, $ldap_port_modify);
}

if (!$ldap_conn_modify) {
    error_log("PROCESS_PWCH: Falha ao conectar ao servidor LDAP para alteracao de senha.");
    header($redirect_to_change_password_error . urlencode("Não foi possível conectar ao servidor LDAP para alterar a senha."));
    exit;
}

ldap_set_option($ldap_conn_modify, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option($ldap_conn_modify, LDAP_OPT_REFERRALS, 0);
ldap_set_option($ldap_conn_modify, LDAP_OPT_NETWORK_TIMEOUT, 5);

// 5. Realizar o bind para a modificação
error_log("PROCESS_PWCH: Realizando bind para operacao de modify com DN: " . $bind_dn_for_modify);
if (!@ldap_bind($ldap_conn_modify, $bind_dn_for_modify, $bind_password_for_modify)) {
    $ldap_errno = ldap_errno($ldap_conn_modify);
    $ldap_errstr = ldap_error($ldap_conn_modify);
    $extended_error = '';
    @ldap_get_option($ldap_conn_modify, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error);

    error_log("PROCESS_PWCH: Falha no bind para operacao de modify: Error [$ldap_errno]: $ldap_errstr. Extended: $extended_error");
    @ldap_close($ldap_conn_modify);

    // Mapeamento de erros comuns do AD para mensagens amigáveis
    $user_error_message = "Não foi possível autenticar sua senha atual para realizar a alteração.";
    if ($ldap_errno == 49) { // Invalid credentials
        $data_code = null;
        if (preg_match('/data\s([0-9a-fA-F]+),/i', $extended_error, $matches)) {
            $data_code = strtolower($matches[1]);
        }
        if ($data_code === '52e') {
            $user_error_message = "Senha atual incorreta. Tente novamente.";
        } elseif ($data_code === '533') {
            $user_error_message = "Sua conta está desabilitada. Contate o suporte.";
        } elseif ($data_code === '775') {
            $user_error_message = "Sua conta foi bloqueada devido a tentativas incorretas. Contate o suporte.";
        } elseif ($data_code === '532' || $data_code === '773') {
            $user_error_message = "Sua senha requer alteração. Confirme sua senha atual."; // Este caso já deveria ter sido pego e o campo desabilitado
        } else {
             $user_error_message = "Senha atual incorreta ou erro de autenticação (cód. $data_code).";
        }
    } else {
        $user_error_message = "Erro de conexão ou autenticação no AD. (cód. $ldap_errno).";
    }

    header($redirect_to_change_password_error . urlencode($user_error_message));
    exit;
}

// 6. Preparar a nova senha para o formato unicodePwd
// A senha precisa estar entre aspas duplas e ser codificada em UTF-16LE
$newPasswordQuoted = "\"" . $newPassword . "\"";
$newPasswordUnicode = mb_convert_encoding($newPasswordQuoted, "UTF-16LE");

$userData = [];
$userData["unicodePwd"] = $newPasswordUnicode;

// 7. Realizar a modificação da senha
error_log("PROCESS_PWCH: Chamando ldap_modify para DN: " . $currentUserDN);
if (@ldap_modify($ldap_conn_modify, $currentUserDN, $userData)) {
    error_log("PROCESS_PWCH: Senha alterada com sucesso para: " . $currentUserDN);
    // Limpar flags de forçar troca e redirecionar com sucesso
    if (isset($_SESSION['force_change_reason'])) {
        unset($_SESSION['force_change_reason']);
    }
    // Opcional: Se for alteração por admin de pwdLastSet=0, você pode querer explicitamente
    // definir pwdLastSet para um valor diferente de 0. No entanto, o AD geralmente faz isso
    // automaticamente após um reset/alteração de senha bem-sucedido.

    @ldap_close($ldap_conn_modify);
    header($redirect_to_index_success . urlencode("Sua senha foi alterada com sucesso!"));
    exit;
} else {
    // Falha na modificação da senha
    $ldap_errno = ldap_errno($ldap_conn_modify);
    $ldap_errstr = ldap_error($ldap_conn_modify);
    $extended_error = '';
    @ldap_get_option($ldap_conn_modify, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error);

    error_log("PROCESS_PWCH: FALHA NA OPERACAO ldap_modify para $currentUserDN. Error [$ldap_errno]: $ldap_errstr. Extended: $extended_error");
    @ldap_close($ldap_conn_modify);

    $user_error_message = "Não foi possível alterar sua senha. Ocorreu um erro inesperado.";
    if ($ldap_errno == 50) { // Insufficient access
        $user_error_message = "Não foi possível alterar a senha: Permissão insuficiente no AD. Verifique as permissões para a conta de serviço ou para autoalteração de senha.";
        error_log("PROCESS_PWCH: DEBUG - ERRO 50: Verificar permissoes 'Reset Password' para admin_dn ou 'Change Password' para user_dn e configuracao LDAPS.");
    } elseif ($ldap_errno == 19) { // Constraint violation (violação da política de senha do AD)
        $user_error_message = "A nova senha não atende à política de senhas do Active Directory (complexidade, histórico, etc.).";
    }

    header($redirect_to_change_password_error . urlencode($user_error_message));
    exit;
}
?>