<?php
require_once 'config.php'; // Carrega session_start(), definições e funções auxiliares

$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username_input = trim($_POST['username'] ?? '');
    $password_input = $_POST['password'] ?? '';

    if (empty($username_input) || empty($password_input)) {
        $error_message = "Usuário e senha são obrigatórios.";
        header("Location: index.php?message=" . urlencode($error_message));
        exit;
    }

    $ldap_conn = null;
    // Tentar conectar ao LDAP primário
    $ldap_port_to_use = defined('LDAP_PORT') ? LDAP_PORT : (strpos(LDAP_SERVER, 'ldaps://') === 0 ? 636 : 389);
    $ldap_conn = @ldap_connect(LDAP_SERVER, $ldap_port_to_use);

    // Se primário falhar e backup estiver definido, tentar backup
    if (!$ldap_conn && defined('LDAP_SERVER_BACKUP') && LDAP_SERVER_BACKUP) {
        $ldap_port_backup_to_use = defined('LDAP_PORT') ? LDAP_PORT : (strpos(LDAP_SERVER_BACKUP, 'ldaps://') === 0 ? 636 : 389);
        $ldap_conn = @ldap_connect(LDAP_SERVER_BACKUP, $ldap_port_backup_to_use);
    }

    if ($ldap_conn) {
        ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldap_conn, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($ldap_conn, LDAP_OPT_NETWORK_TIMEOUT, 5); // Timeout para operações de rede

        // Determinar o formato do bind DN do usuário
        $ldap_user_bind_dn = '';
        if (strpos(LDAP_DOMAIN, '.') !== false) { // Verifica se LDAP_DOMAIN parece um FQDN (ex: specto.local)
            $ldap_user_bind_dn = $username_input . "@" . LDAP_DOMAIN;
        } else { // Assume que é um nome NetBIOS (ex: SPECTO)
            $ldap_user_bind_dn = LDAP_DOMAIN . "\\" . $username_input;
        }

        // Tentar autenticar (bind) com as credenciais do usuário
        if (@ldap_bind($ldap_conn, $ldap_user_bind_dn, $password_input)) {
            // Autenticação bem-sucedida!
            $_SESSION['username'] = $username_input;
            // O user_dn será buscado em index.php após o redirecionamento,
            // usando o ldap_connect_admin() para mais segurança e consistência.
            
            @ldap_close($ldap_conn);
            header("Location: index.php"); // Redireciona para a página principal/status
            exit;
        } else {
            // Falha na autenticação
            $ldap_errno = ldap_errno($ldap_conn);
            $ldap_errstr = ldap_error($ldap_conn);
            $extended_ldap_error = '';
            @ldap_get_option($ldap_conn, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extended_ldap_error);

            error_log("LDAP User Bind Failed for user '$username_input' (Bind DN: '$ldap_user_bind_dn'). Error [$ldap_errno]: $ldap_errstr. Extended: $extended_ldap_error");

            if ($ldap_errno == 49) { // Erro 49: Credenciais Inválidas
                $data_code = null;
                if (preg_match('/data\s([0-9a-fA-F]+),/i', $extended_ldap_error, $matches)) {
                    $data_code = strtolower($matches[1]);
                }

                // Verificar sub-códigos específicos do AD
                if ($data_code === '532') { // Senha expirada
                    $error_message = "Sua senha expirou. Você precisa alterá-la.";
                    $_SESSION['force_change_reason'] = $error_message;
                } elseif ($data_code === '773') { // Usuário deve alterar senha no próximo logon
                    $error_message = "Você deve alterar sua senha no primeiro logon ou porque ela foi redefinida.";
                    $_SESSION['force_change_reason'] = $error_message;
                } elseif ($data_code === '533') { // Conta desabilitada
                    $error_message = "Sua conta está desabilitada. Contate o suporte.";
                } elseif ($data_code === '775') { // Conta bloqueada
                    $error_message = "Sua conta foi bloqueada devido a múltiplas tentativas de login falhas. Contate o suporte.";
                } elseif ($data_code === '525') { // Usuário não encontrado (improvável se o formato do bind DN estiver correto)
                    $error_message = "Usuário não encontrado. Verifique o nome de usuário.";
                } elseif ($data_code === '52e') { // Senha incorreta
                    $error_message = "Usuário ou senha inválidos.";
                } else { // Outro erro dentro do escopo de credenciais inválidas
                    $error_message = "Usuário ou senha inválidos (detalhe no log).";
                }
                
                // Se for um caso de troca de senha obrigatória e o usuário existe
                if ($data_code === '532' || $data_code === '773') {
                    // Para redirecionar para change_password.php, precisamos do user_dn.
                    // Tentaremos obtê-lo com a conta de admin, já que o bind do usuário falhou.
                    $admin_conn_for_dn = ldap_connect_admin(); // Função de config.php
                    if ($admin_conn_for_dn) {
                        $filter_for_dn = "(sAMAccountName=" . ldap_escape($username_input, "", LDAP_ESCAPE_FILTER) . ")";
                        $search_res_dn = @ldap_search($admin_conn_for_dn, LDAP_BASE_DN, $filter_for_dn, ["dn"]);
                        if ($search_res_dn) {
                            $entries_dn = @ldap_get_entries($admin_conn_for_dn, $search_res_dn);
                            if ($entries_dn && $entries_dn['count'] > 0) {
                                $_SESSION['user_dn'] = $entries_dn[0]['dn'];
                                $_SESSION['username'] = $username_input; // Garante que o username está na sessão
                                @ldap_close($admin_conn_for_dn);
                                @ldap_close($ldap_conn);
                                header("Location: change_password.php");
                                exit;
                            }
                        }
                        @ldap_close($admin_conn_for_dn);
                        // Se não conseguiu obter o DN, cairá no erro genérico abaixo.
                        $error_message .= " Não foi possível obter informações adicionais da conta.";
                    } else {
                        $error_message .= " Falha ao conectar como admin para obter DN.";
                    }
                }

            } else { // Outros erros LDAP (ex: servidor indisponível após a tentativa de conexão inicial)
                $error_message = "Erro de autenticação LDAP. Contate o suporte. (Erro: $ldap_errstr)";
            }
            @ldap_close($ldap_conn);
        }
    } else {
        $error_message = "Não foi possível conectar ao servidor LDAP. Verifique o status da conexão no portal ou contate o suporte.";
    }

    // Se chegou aqui, houve um erro que não redirecionou para change_password.php
    header("Location: index.php?message=" . urlencode($error_message));
    exit;

} else {
    // Se não for POST, redireciona para a página inicial
    header("Location: index.php");
    exit;
}
?>