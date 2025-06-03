<?php
require_once 'config.php'; // Carrega session_start(), definições e funções auxiliares

// Inicialização de variáveis
$error_message = '';
$success_message = '';
$user_info = null;
$force_change_password = false;
$is_account_active = true; // Assumir ativo por padrão até que seja verificado

// 1. Verificar o status da conexão LDAP para exibição
$ldap_status_info = check_ldap_server_status();

// 2. Verificar se o usuário já está logado (sessão existe)
if (isset($_SESSION['username'])) {
    $username_from_session = $_SESSION['username'];
    $ldap_conn_admin = ldap_connect_admin(); // Função de config.php para conectar com usuário de serviço

    if ($ldap_conn_admin) {
        $filter = "(sAMAccountName=" . ldap_escape($username_from_session, "", LDAP_ESCAPE_FILTER) . ")";
        $attributes = ["dn", "pwdlastset", "useraccountcontrol", "msds-userpasswordexpirytimecomputed", "name", "displayname"];
        $search_result = @ldap_search($ldap_conn_admin, LDAP_BASE_DN, $filter, $attributes);

        if ($search_result) {
            $entries = @ldap_get_entries($ldap_conn_admin, $search_result);

            if ($entries && $entries['count'] > 0) {
                $user_data = $entries[0];
                $_SESSION['user_dn'] = $user_data['dn']; // Guardar DN para troca de senha

                $uac = $user_data['useraccountcontrol'][0];
                $displayName = $user_data['displayname'][0] ?? $user_data['name'][0] ?? $username_from_session;

                // Verificar se a conta está desabilitada
                if ($uac & UAC_ACCOUNT_DISABLED) {
                    $is_account_active = false;
                    $error_message = "Sua conta (" . htmlspecialchars($username_from_session) . ") está desativada. Entre em contato com o suporte.";
                    // Limpar sessão se a conta estiver desativada
                    session_unset(); // Remove todas as variáveis de sessão
                    session_destroy(); // Destrói a sessão
                    // Não precisa de header() aqui, a página vai renderizar com a mensagem de erro e sem formulário de usuário.
                } else {
                    $is_account_active = true;
                    $password_never_expires = (bool)($uac & UAC_DONT_EXPIRE_PASSWORD);
                    $pwdLastSet = $user_data['pwdlastset'][0];
                    $is_first_login_change_required = ($pwdLastSet == "0");
                    $last_password_set_timestamp = null;
                    $last_password_set_date = "N/A";

                    if (!$is_first_login_change_required) {
                        $last_password_set_timestamp = convertAdTime($pwdLastSet);
                        $last_password_set_date = formatDate($last_password_set_timestamp);
                    }

                    $days_to_expire = null;

                    if ($is_first_login_change_required) {
                        $force_change_password = true;
                        $_SESSION['force_change_reason'] = "Este é seu primeiro acesso ou sua senha foi redefinida. Você precisa definir uma nova senha.";
                    } elseif (!$password_never_expires) {
                        if (isset($user_data['msds-userpasswordexpirytimecomputed'][0])) {
                            $expiry_timestamp_ad = $user_data['msds-userpasswordexpirytimecomputed'][0];
                            // "Never" or "Not Set" or very far future date might mean it's effectively not expiring soon by this attribute
                            if ($expiry_timestamp_ad != "0" && $expiry_timestamp_ad != "9223372036854775807") {
                                $expiry_timestamp_unix = convertAdTime($expiry_timestamp_ad);
                                if ($expiry_timestamp_unix) {
                                    $now = time();
                                    if ($expiry_timestamp_unix < $now) {
                                        $force_change_password = true;
                                        $days_to_expire = 0; // Já expirou
                                        $_SESSION['force_change_reason'] = "Sua senha expirou em " . formatDate($expiry_timestamp_unix) . ".";
                                    } else {
                                        $days_to_expire = floor(($expiry_timestamp_unix - $now) / (60 * 60 * 24));
                                    }
                                }
                            }
                        } else if ($last_password_set_timestamp) { // Fallback se msDS-UserPasswordExpiryTimeComputed não estiver disponível
                            $expiry_timestamp_unix = $last_password_set_timestamp + (PASSWORD_EXPIRES_DAYS * 24 * 60 * 60);
                            $now = time();
                            if ($expiry_timestamp_unix < $now) {
                                $force_change_password = true;
                                $days_to_expire = 0; // Já expirou
                                $_SESSION['force_change_reason'] = "Sua senha expirou (calculado pela data da última alteração).";
                            } else {
                                $days_to_expire = floor(($expiry_timestamp_unix - $now) / (60 * 60 * 24));
                            }
                        }
                    }

                    if ($is_account_active) { // Só preenche user_info se a conta estiver ativa
                        $user_info = [
                            'name' => $displayName,
                            'username' => $username_from_session,
                            'last_password_set' => $last_password_set_date,
                            'password_never_expires' => $password_never_expires,
                            'is_first_login' => $is_first_login_change_required,
                            'days_to_expire' => $days_to_expire,
                            'account_active' => $is_account_active
                        ];

                        if ($force_change_password) {
                            // Redirecionar para a página de troca de senha
                            header("Location: change_password.php");
                            exit;
                        }
                    }
                } // fim do else $uac & UAC_ACCOUNT_DISABLED
            } else {
                // Usuário da sessão não encontrado no LDAP, limpar sessão
                $error_message = "Usuário da sessão (" . htmlspecialchars($username_from_session) . ") não encontrado no LDAP. Faça login novamente.";
                session_unset();
                session_destroy();
            }
        } else {
            $error_message = "Erro na busca LDAP ao verificar usuário da sessão: " . htmlspecialchars(ldap_error($ldap_conn_admin));
            // Considerar limpar sessão aqui também se o erro for grave
        }
        @ldap_close($ldap_conn_admin);
    } else {
        // Não foi possível conectar com o admin bind para buscar dados do usuário logado
        $error_message = "Não foi possível conectar ao servidor LDAP para verificar sua sessão. Tente mais tarde.";
        // Manter o usuário logado na sessão, mas ele não verá detalhes da senha.
        // Ou, alternativamente, deslogá-lo:
        // session_unset();
        // session_destroy();
    }
}

// 3. Pegar mensagens de GET (após possíveis redirecionamentos)
if (isset($_GET['message'])) {
    $error_message = htmlspecialchars($_GET['message']);
}
if (isset($_GET['success_message'])) {
    $success_message = htmlspecialchars($_GET['success_message']);
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portal de Senha - Specto</title>
    <link rel="stylesheet" href="css/style.css">
    <style> /* Estilos rápidos para o status LDAP, idealmente mova para style.css */
        .ldap-status-box {
            border: 1px solid #ddd;
            padding: 10px 15px;
            margin-bottom: 20px;
            background-color: #f0f0f0; /* Tom de cinza mais claro */
            border-radius: 5px;
            font-size: 0.9em;
        }
        .ldap-status-box h4 {
            margin-top: 0;
            margin-bottom: 8px;
            color: #333;
        }
        .ldap-status-box p {
            margin: 4px 0;
            line-height: 1.4;
        }
        .status-online { color: #28a745; /* Verde */ font-weight: bold; }
        .status-offline { color: #dc3545; /* Vermelho */ font-weight: bold; }
        .status-unavailable { color: #ffc107; /* Amarelo */ font-weight: bold; }
        .status-detail { font-size: 0.85em; color: #555; }
    </style>
</head>
<body>
    <header>
        <a href="index.php" class="logo-link">
            <img src="img/logo.png" alt="Logo Specto" class="header-logo">
        </a>
        <h1 class="header-title">Portal de Senha Specto</h1>
    </header>
    <main>
        <div class="ldap-status-box">
            <h4>Status da Conexão LDAP: <span class="<?php echo strpos($ldap_status_info['overall_status'], 'Inativa') !== false ? 'status-offline' : 'status-online'; ?>"><?php echo htmlspecialchars($ldap_status_info['overall_status']); ?></span></h4>
            <p>Conectado a: <strong><?php echo htmlspecialchars($ldap_status_info['connected_to']); ?></strong>
                <?php if ($ldap_status_info['active_connection'] === 'primary'): ?>
                    (Servidor Principal)
                <?php elseif ($ldap_status_info['active_connection'] === 'backup'): ?>
                    (Servidor de Backup)
                <?php endif; ?>
            </p>
            <hr style="border: 0; border-top: 1px solid #eee; margin: 8px 0;">
            <p>Servidor Principal (<?php echo htmlspecialchars($ldap_status_info['primary_server_host']); ?>):
                <span class="<?php echo $ldap_status_info['primary_status'] === 'Online' ? 'status-online' : 'status-offline'; ?>">
                    <?php echo htmlspecialchars($ldap_status_info['primary_status']); ?>
                </span>
                <?php if ($ldap_status_info['primary_error']): ?>
                    <span class="status-detail">(Detalhe: <?php echo htmlspecialchars($ldap_status_info['primary_error']); ?>)</span>
                <?php endif; ?>
            </p>
            <?php if ($ldap_status_info['backup_server_host']): ?>
            <p>Servidor de Backup (<?php echo htmlspecialchars($ldap_status_info['backup_server_host']); ?>):
                <span class="<?php
                    if ($ldap_status_info['backup_status'] === 'Online' || $ldap_status_info['backup_status'] === 'Online (Disponível)') {
                        echo 'status-online';
                    } elseif ($ldap_status_info['backup_status'] === 'Não Configurado') {
                        echo 'status-detail';
                    } else {
                        echo 'status-offline';
                    }
                ?>">
                    <?php echo htmlspecialchars($ldap_status_info['backup_status']); ?>
                </span>
                <?php if ($ldap_status_info['backup_error']): ?>
                    <span class="status-detail">(Detalhe: <?php echo htmlspecialchars($ldap_status_info['backup_error']); ?>)</span>
                <?php endif; ?>
            </p>
            <?php endif; ?>
        </div>

        <?php if (!empty($error_message)): ?>
            <p class="error"><?php echo $error_message; ?></p>
        <?php endif; ?>
        <?php if (!empty($success_message)): ?>
            <p class="success"><?php echo $success_message; ?></p>
        <?php endif; ?>

        <?php if ($user_info && $is_account_active): ?>
            <h2>Olá, <?php echo htmlspecialchars($user_info['name']); ?>!</h2>
            <p>Usuário de rede: <?php echo htmlspecialchars($user_info['username']); ?></p>

            <?php if ($user_info['password_never_expires']): ?>
                <p class="status-normal">✅ Sua senha está configurada para <strong>nunca expirar</strong>.</p>
            <?php elseif ($user_info['is_first_login']): ?>
                <?php /* Esta condição já deve ter causado um redirecionamento, mas como fallback: */ ?>
                <p class="status-warning">⚠️ Este é seu primeiro acesso ou sua senha foi redefinida. Você precisa <a href="change_password.php">definir uma nova senha</a>.</p>
            <?php else: ?>
                <p>Última alteração de senha: <?php echo $user_info['last_password_set']; ?></p>
                <?php if ($user_info['days_to_expire'] !== null): ?>
                    <?php if ($user_info['days_to_expire'] > 15): ?>
                        <p class="status-normal">Sua senha expira em: <strong><?php echo $user_info['days_to_expire']; ?> dias</strong>.</p>
                    <?php elseif ($user_info['days_to_expire'] > 0): ?>
                        <p class="status-warning">⚠️ ATENÇÃO: Sua senha expira em: <strong><?php echo $user_info['days_to_expire']; ?> dias</strong>.</p>
                    <?php else: ?>
                         <?php /* Esta condição também já deve ter causado um redirecionamento */ ?>
                        <p class="status-expired">📛 Sua senha expirou! Você precisa <a href="change_password.php">alterá-la agora</a>.</p>
                    <?php endif; ?>
                <?php else: ?>
                     <p>Não foi possível determinar a data de expiração da sua senha.</p>
                <?php endif; ?>
            <?php endif; ?>
            <br>
            <?php // NOVO AJUSTE: Exibir botão Alterar Senha apenas se a senha NÃO for configurada para nunca expirar ?>
            <?php if (!$user_info['password_never_expires']): ?>
                <a href="change_password.php" class="button">Alterar Minha Senha</a>
            <?php endif; ?>
            <a href="logout.php" class="button">Sair</a>

        <?php elseif (isset($_SESSION['username']) && !$is_account_active): ?>
            <a href="logout.php" class="button">Sair</a>
        <?php else: ?>
            <h2>Login</h2>
            <form action="login.php" method="post">
                <div>
                    <label for="username">Usuário de Rede (Ex: seu.usuario):</label>
                    <input type="text" id="username" name="username" required autocomplete="username">
                </div>
                <div>
                    <label for="password">Senha Atual:</label>
                    <input type="password" id="password" name="password" required autocomplete="current-password">
                </div>
                <button type="submit">Entrar</button>
            </form>
        <?php endif; ?>
    </main>
    <footer>
    <p>&copy; <?php echo date("Y"); ?> Specto Tecnologia - Portal de Senha | Desenvolvido por <a href="https://www.linkedin.com/in/paulo-f-santos/" class="developer-link" target="_blank">Paulo Francisco dos Santos</a></p>

    </footer>
</body>
</html>
    