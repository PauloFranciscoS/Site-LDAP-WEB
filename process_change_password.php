<?php
require_once 'config.php'; // Carrega configurações LDAP, funções e session_start()

// --- NOVO: DEBUG - Log de Entrada de Dados ---
// REMOVER OU GERENCIAR ESTAS LINHAS EM PRODUÇÃO PARA EVITAR VAZAMENTO DE INFORMAÇÕES SENSÍVEIS
// error_log("PROCESS_PWCH DEBUG: Script iniciado.");
// error_log("PROCESS_PWCH DEBUG: SESSION - username: " . ($_SESSION['username'] ?? 'N/A') . ", user_dn: " . ($_SESSION['user_dn'] ?? 'N/A'));
// error_log("PROCESS_PWCH DEBUG: POST - current_password_skipped: " . (isset($_POST['current_password_skipped']) ? 'true' : 'false'));
// error_log("PROCESS_PWCH DEBUG: POST - new_password (length): " . strlen($_POST['new_password'] ?? '') . ", confirm_password (length): " . strlen($_POST['confirm_password'] ?? ''));
// --- FIM NOVO DEBUG ---

// Redireciona se o usuário não estiver logado
if (!isset($_SESSION['username']) || !isset($_SESSION['user_dn'])) {
    error_log("PROCESS_PWCH ERROR: Sessao invalida ou usuario nao encontrado. Redirecionando para index.php.");
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
    error_log("PROCESS_PWCH ERROR: Nova senha ou confirmacao vazias.");
    header($redirect_to_change_password_error . urlencode("Nova senha e confirmação são obrigatórias."));
    exit;
}
if ($newPassword !== $confirmPassword) {
    error_log("PROCESS_PWCH ERROR: Novas senhas nao coincidem.");
    header($redirect_to_change_password_error . urlencode("As novas senhas não coincidem."));
    exit;
}
if (!preg_match(PASSWORD_POLICY_REGEX, $newPassword)) {
    $policyError = "A nova senha não atende aos requisitos: Mínimo 14 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais.";
    error_log("PROCESS_PWCH ERROR: Politica de senha nao atendida para a nova senha. Regex: " . PASSWORD_POLICY_REGEX);
    header($redirect_to_change_password_error . urlencode($policyError));
    exit;
}

// 2. Conectar ao LDAP para verificar o status do usuário (pwdLastSet)
// Esta etapa ainda é útil para logging ou para qualquer lógica futura baseada no estado da conta.
error_log("PROCESS_PWCH INFO: Tentando conectar como admin para verificar pwdLastSet do usuario: " . $currentUserDN);
$ldap_conn_check_user = ldap_connect_admin(); // Conecta como admin para ler atributos do usuário
if (!$ldap_conn_check_user) {
    error_log("PROCESS_PWCH ERROR: Falha ao conectar como admin para verificar pwdLastSet do usuario: " . (ldap_error(null) ?? 'Erro desconhecido na conexao LDAP geral'));
    header($redirect_to_change_password_error . urlencode("Erro interno ao verificar seu status. Contate o suporte."));
    exit;
}

$filter_user_dn = "(distinguishedName=" . ldap_escape($currentUserDN, "", LDAP_ESCAPE_FILTER) . ")";
$attrs_user_check = ["dn", "pwdlastset", "useraccountcontrol"]; // Adicione 'dn' para garantir
error_log("PROCESS_PWCH INFO: Buscando atributos do usuario ($currentUserDN) com filtro: $filter_user_dn");
$search_user_check = @ldap_read($ldap_conn_check_user, $currentUserDN, $filter_user_dn, $attrs_user_check);

if (!$search_user_check) {
    error_log("PROCESS_PWCH ERROR: Falha na busca de atributos do usuario ($currentUserDN) para verificar pwdLastSet: " . ldap_error($ldap_conn_check_user));
    @ldap_close($ldap_conn_check_user); // Fechar conexão admin antes de sair
    header($redirect_to_change_password_error . urlencode("Não foi possível verificar seu status no AD. Contate o suporte."));
    exit;
}

$entries_user_check = @ldap_get_entries($ldap_conn_check_user, $search_user_check);
@ldap_close($ldap_conn_check_user); // Fechar conexão admin após a leitura

if (!$entries_user_check || $entries_user_check['count'] == 0) {
    error_log("PROCESS_PWCH ERROR: Usuario ($currentUserDN) nao encontrado no AD para verificar pwdLastSet.");
    header($redirect_to_change_password_error . urlencode("Sua conta não foi encontrada no Active Directory. Contate o suporte."));
    exit;
}

$pwdLastSet = $entries_user_check[0]['pwdlastset'][0];
$is_first_login_or_reset = ($pwdLastSet == "0");
error_log("PROCESS_PWCH INFO: pwdLastSet para $currentUserDN: $pwdLastSet. Primeiro acesso/reset detectado: " . ($is_first_login_or_reset ? 'Sim' : 'Não'));

// NOVO: 3.1. Validar a Senha Atual para trocas normais (se não for primeiro acesso/reset e não foi pulada)
if (!$is_first_login_or_reset && !$currentPasswordSkipped) {
    if (empty($currentPassword)) {
        error_log("PROCESS_PWCH ERROR: Senha atual vazia para troca de senha normal.");
        header($redirect_to_change_password_error . urlencode("A senha atual é obrigatória para alterar a senha."));
        exit;
    }

    // Tentar autenticar o usuário com a senha atual fornecida
    $ldap_conn_auth = null;
    $ldap_port_auth = defined('LDAP_PORT') ? LDAP_PORT : 636;
    $ldap_conn_auth = @ldap_connect(LDAP_SERVER, $ldap_port_auth);

    if (!$ldap_conn_auth && defined('LDAP_SERVER_BACKUP') && LDAP_SERVER_BACKUP) {
        $ldap_conn_auth = @ldap_connect(LDAP_SERVER_BACKUP, $ldap_port_auth);
    }

    if (!$ldap_conn_auth) {
        error_log("PROCESS_PWCH ERROR: Falha ao conectar ao servidor LDAP para validar senha atual.");
        header($redirect_to_change_password_error . urlencode("Erro interno ao validar a senha atual. Por favor, tente novamente mais tarde."));
        exit;
    }

    ldap_set_option($ldap_conn_auth, LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($ldap_conn_auth, LDAP_OPT_REFERRALS, 0);
    ldap_set_option($ldap_conn_auth, LDAP_OPT_NETWORK_TIMEOUT, 5);

    $bind_dn_for_auth = $_SESSION['user_dn']; // Usar o DN completo do usuário
    if (!@ldap_bind($ldap_conn_auth, $bind_dn_for_auth, $currentPassword)) {
        $ldap_errno_auth = ldap_errno($ldap_conn_auth);
        $ldap_errstr_auth = ldap_error($ldap_conn_auth);
        $extended_error_auth = '';
        @ldap_get_option($ldap_conn_auth, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error_auth);

        error_log("PROCESS_PWCH ERROR: Falha na validacao da senha atual para $currentUserDN. Error [$ldap_errno_auth]: $ldap_errstr_auth. Extended: $extended_error_auth");
        @ldap_close($ldap_conn_auth);

        // Mensagem mais genérica para o usuário final, sem dar dicas sobre a senha atual
        if ($ldap_errno_auth == 49) { // Invalid credentials (senha incorreta, conta bloqueada, etc.)
            header($redirect_to_change_password_error . urlencode("A senha atual fornecida está incorreta ou sua conta pode estar bloqueada."));
        } elseif ($ldap_errno_auth == -1) { // Can't contact LDAP server
            header($redirect_to_change_password_error . urlencode("Erro de conexão ao servidor LDAP ao validar a senha atual."));
        } else {
            header($redirect_to_change_password_error . urlencode("Não foi possível validar sua senha atual. Código de erro: $ldap_errno_auth."));
        }
        exit;
    }
    @ldap_close($ldap_conn_auth);
    error_log("PROCESS_PWCH INFO: Senha atual validada com sucesso para $currentUserDN.");
}


// 3. Determinar o contexto de bind para a operação de alteração de senha
// --- AJUSTE AQUI: SEMPRE USA AS CREDENCIAIS DO ADMIN_DN PARA O BIND ---
$bind_dn_for_modify = LDAP_ADMIN_DN;
$bind_password_for_modify = LDAP_ADMIN_PASSWORD;
$current_password_required = false; // A senha atual do usuário NÃO é mais necessária para o bind de modificação.
error_log("PROCESS_PWCH INFO: Forcando bind com ADMIN_DN para alteracao de senha do usuario " . $currentUserDN);

// O bloco 'if ($is_first_login_or_reset)' original não é mais necessário aqui para definir o bind,
// mas a variável $is_first_login_or_reset ainda é útil para fins de logging ou exibição.
// Se você quiser manter a lógica original de log ou mensagem:
if ($is_first_login_or_reset) {
    error_log("PROCESS_PWCH INFO: Usuario ($currentUsername) em cenario de 'primeiro acesso/reset' (pwdLastSet=0).");
} else {
    error_log("PROCESS_PWCH INFO: Usuario ($currentUsername) em cenario de 'troca de senha normal'.");
}

// 4. Conectar ao LDAP para realizar a modificação
$ldap_conn_modify = null;
$ldap_port_modify = defined('LDAP_PORT') ? LDAP_PORT : 636; // Usa 636 como padrão para LDAPS

error_log("PROCESS_PWCH INFO: Tentando conectar ao servidor LDAP primario (" . LDAP_SERVER . ":$ldap_port_modify) para alteracao de senha.");
$ldap_conn_modify = @ldap_connect(LDAP_SERVER, $ldap_port_modify);
// Se primário falhar e backup estiver definido, tentar backup
if (!$ldap_conn_modify && defined('LDAP_SERVER_BACKUP') && LDAP_SERVER_BACKUP) {
    error_log("PROCESS_PWCH WARNING: Conexao com servidor primario falhou. Tentando servidor de backup (" . LDAP_SERVER_BACKUP . ":$ldap_port_modify).");
    $ldap_conn_modify = @ldap_connect(LDAP_SERVER_BACKUP, $ldap_port_modify);
}

if (!$ldap_conn_modify) {
    error_log("PROCESS_PWCH ERROR: Falha ao conectar ao servidor LDAP (primario e/ou backup) para alteracao de senha. Erro ldap_connect: " . (ldap_error(null) ?? 'desconhecido'));
    header($redirect_to_change_password_error . urlencode("Não foi possível conectar ao servidor LDAP para alterar a senha."));
    exit;
}

ldap_set_option($ldap_conn_modify, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option($ldap_conn_modify, LDAP_OPT_REFERRALS, 0);
ldap_set_option($ldap_conn_modify, LDAP_OPT_NETWORK_TIMEOUT, 5); // Timeout para operações de rede

// 5. Realizar o bind para a modificação
error_log("PROCESS_PWCH INFO: Realizando bind para operacao de modify com DN: " . $bind_dn_for_modify);
if (!@ldap_bind($ldap_conn_modify, $bind_dn_for_modify, $bind_password_for_modify)) {
    $ldap_errno = ldap_errno($ldap_conn_modify);
    $ldap_errstr = ldap_error($ldap_conn_modify);
    $extended_error = '';
    @ldap_get_option($ldap_conn_modify, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error);

    error_log("PROCESS_PWCH ERROR: Falha no bind com ADMIN_DN para operacao de modify. Bind DN: $bind_dn_for_modify. Error [$ldap_errno]: $ldap_errstr. Extended: $extended_error");
    @ldap_close($ldap_conn_modify);

    // Se o bind falhou aqui, é porque as credenciais da conta de serviço (LDAP_ADMIN_DN) estão incorretas
    // ou há um problema de conexão/permissão para o próprio admin_dn.
    $user_error_message = "Erro interno: Falha ao autenticar a conta de serviço no AD. Contate o suporte.";

    if ($ldap_errno == 49) { // Invalid credentials
        $data_code = null;
        if (preg_match('/data\s([0-9a-fA-F]+),/i', $extended_error, $matches)) {
            $data_code = strtolower($matches[1]);
        }
        error_log("PROCESS_PWCH ERROR: LDAP error 49 (Invalid credentials) for ADMIN_DN with data code: " . ($data_code ?? 'N/A'));

        if ($data_code === '52e') {
            $user_error_message = "Erro interno: A senha da conta de serviço no AD está incorreta. Contate o suporte.";
        } elseif ($data_code === '533') {
            $user_error_message = "Erro interno: A conta de serviço no AD está desabilitada. Contate o suporte.";
        } elseif ($data_code === '775') {
            $user_error_message = "Erro interno: A conta de serviço no AD foi bloqueada. Contate o suporte.";
        } else {
             $user_error_message = "Erro interno: Problema de autenticação da conta de serviço (cód. $data_code). Contate o suporte.";
        }
    } elseif ($ldap_errno == -1) { // Can't contact LDAP server
        $user_error_message = "Erro de conexão ao servidor LDAP. Verifique a configuração ou status do AD.";
    } else {
        $user_error_message = "Erro de autenticação da conta de serviço no AD (cód. $ldap_errno). Contate o suporte.";
    }

    header($redirect_to_change_password_error . urlencode($user_error_message));
    exit;
}

// 6. Preparar a nova senha para o formato unicodePwd
$newPasswordQuoted = "\"" . $newPassword . "\"";
$newPasswordUnicode = mb_convert_encoding($newPasswordQuoted, "UTF-16LE");

$userData = [];
$userData["unicodePwd"] = $newPasswordUnicode;

// 7. Realizar a modificação da senha
error_log("PROCESS_PWCH INFO: Chamando ldap_modify para DN: " . $currentUserDN . " com a nova senha.");
if (@ldap_modify($ldap_conn_modify, $currentUserDN, $userData)) {
    error_log("PROCESS_PWCH SUCCESS: Senha alterada com sucesso para: " . $currentUserDN);
    // Limpar flags de forçar troca e redirecionar com sucesso
    if (isset($_SESSION['force_change_reason'])) {
        unset($_SESSION['force_change_reason']);
    }

    @ldap_close($ldap_conn_modify);
    header($redirect_to_index_success . urlencode("Sua senha foi alterada com sucesso!"));
    exit;
} else {
    // Falha na modificação da senha
    $ldap_errno = ldap_errno($ldap_conn_modify);
    $ldap_errstr = ldap_error($ldap_conn_modify);
    $extended_error = '';
    @ldap_get_option($ldap_conn_modify, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_error);

    error_log("PROCESS_PWCH FATAL ERROR: FALHA NA OPERACAO ldap_modify para $currentUserDN. Error [$ldap_errno]: $ldap_errstr. Extended: $extended_error");
    @ldap_close($ldap_conn_modify);

    $user_error_message = "Não foi possível alterar sua senha. Ocorreu um erro inesperado.";
    if ($ldap_errno == 50) { // Insufficient access
        $user_error_message = "Não foi possível alterar a senha: Permissão insuficiente no Active Directory. Contate o suporte."; // Ajustado para focar na conta de serviço
        error_log("PROCESS_PWCH DEBUG: ERRO 50 - DEBUG: Verificar permissoes 'Reset Password' para admin_dn no OU/Container onde o usuario reside.");
    } elseif ($ldap_errno == 19) { // Constraint violation (violação da política de senha do AD)
        $user_error_message = "A nova senha não atende à política de senhas do Active Directory (complexidade, histórico, tempo mínimo de alteração, etc.). Por favor, revise os requisitos da senha e tente novamente.";
    } else {
        $user_error_message .= " Código de erro: $ldap_errno.";
    }

    header($redirect_to_change_password_error . urlencode($user_error_message));
    exit;
}
?>