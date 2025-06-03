<?php
require_once 'config.php'; // Carrega session_start(), definições e funções auxiliares

// Redireciona se o usuário não estiver logado
if (!isset($_SESSION['username'])) {
    header("Location: index.php?message=" . urlencode("Você precisa estar logado para trocar a senha."));
    exit;
}

$error_message = '';
$success_message = '';
// Pega a razão da mudança forçada da sessão, se existir
$force_change_reason = $_SESSION['force_change_reason'] ?? null;
// Limpa a razão da sessão para que não apareça novamente se a página for recarregada sem um novo redirecionamento
if (isset($_SESSION['force_change_reason'])) {
    unset($_SESSION['force_change_reason']);
}


if (isset($_GET['error'])) {
    $error_message = htmlspecialchars($_GET['error']);
}
if (isset($_GET['success'])) { // Embora esta página raramente mostre msg de sucesso, pois redireciona
    $success_message = htmlspecialchars($_GET['success']);
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alterar Senha - Specto</title>
    <link rel="stylesheet" href="css/style.css">
    <script>
        // Função para validar a política de senha
        function validatePasswordPolicy(password) {
            const regex = <?php echo PASSWORD_POLICY_REGEX; ?>;
            return regex.test(password);
        }

        // Função para verificar as senhas e o estado do formulário
        function checkPassword() {
            const passwordInput = document.getElementById('new_password');
            const confirmPasswordInput = document.getElementById('confirm_password');
            
            // Assegura que os elementos existem antes de tentar acessar seus valores
            if (!passwordInput || !confirmPasswordInput) {
                return;
            }

            const password = passwordInput.value;
            const confirmPassword = confirmPasswordInput.value;
            const message = document.getElementById('password_message');
            const policyMessage = document.getElementById('password_policy_message');
            const submitButton = document.getElementById('submit_button');

            // Assegura que os elementos de mensagem e o botão existem
            if (!message || !policyMessage || !submitButton) {
                return;
            }

            // Se ambos os campos estiverem vazios, limpa mensagens e desabilita o botão
            if (password === "" && confirmPassword === "") {
                message.innerHTML = "";
                policyMessage.innerHTML = "";
                submitButton.disabled = true;
                return;
            }
            
            let isPolicyMet = false;
            // Validação da política de senha
            if (password !== "") { // Só valida a política se a nova senha não estiver vazia
                if (!validatePasswordPolicy(password)) {
                    policyMessage.innerHTML = '❌ A senha deve ter no mínimo 14 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais.';
                    policyMessage.className = 'error'; // Classe para estilizar erro
                    isPolicyMet = false;
                } else {
                    policyMessage.innerHTML = '✅ Política de senha atendida!';
                    policyMessage.className = 'success'; // Classe para estilizar sucesso
                    isPolicyMet = true;
                }
            } else {
                policyMessage.innerHTML = ""; // Limpa se a senha estiver vazia
                isPolicyMet = false; 
            }

            let passwordsMatch = false;
            // Validação da confirmação de senha
            if (confirmPassword !== "" || password !== "") { // Só valida se um dos campos tiver algo
                if (password !== confirmPassword) {
                    message.innerHTML = '❌ As senhas não coincidem!';
                    message.className = 'error';
                    passwordsMatch = false;
                } else {
                    if (password !== "") { // Só mostra mensagem de "coincidem" se a senha não estiver vazia
                         message.innerHTML = '✅ As senhas coincidem!';
                         message.className = 'success';
                    } else {
                        message.innerHTML = ''; // Limpa se vazia
                    }
                    passwordsMatch = true;
                }
            } else {
                 message.innerHTML = ""; // Limpa se ambos vazios
                 passwordsMatch = true; 
            }
            
            // Habilitar botão apenas se a política for atendida, as senhas coincidirem E a nova senha não estiver vazia.
            if (isPolicyMet && passwordsMatch && password !== "") {
                submitButton.disabled = false;
            } else {
                submitButton.disabled = true;
            }
        }

        // Chamar checkPassword no carregamento da página para definir o estado inicial do botão
        // (útil se os campos forem preenchidos automaticamente pelo navegador)
        window.onload = function() {
            checkPassword(); 
            // Adiciona os event listeners após o carregamento completo da página e dos elementos
            const newPasswordInput = document.getElementById('new_password');
            const confirmPasswordInput = document.getElementById('confirm_password');
            if (newPasswordInput) {
                newPasswordInput.addEventListener('keyup', checkPassword);
                newPasswordInput.addEventListener('input', checkPassword); // Para cobrir colar texto
            }
            if (confirmPasswordInput) {
                confirmPasswordInput.addEventListener('keyup', checkPassword);
                confirmPasswordInput.addEventListener('input', checkPassword);
            }
        };
    </script>
</head>
<body>
    <header>
        <a href="index.php" class="logo-link"> <img src="img/logo.png" alt="Logo Specto" class="header-logo"> </a>
        <h1 class="header-title">Alterar Senha</h1> </header>
    <main>
        <?php if ($error_message): ?>
            <p class="error"><?php echo $error_message; ?></p>
        <?php endif; ?>
        <?php if ($success_message): ?>
            <p class="success"><?php echo $success_message; ?></p>
        <?php endif; ?>
        <?php if ($force_change_reason): ?>
            <p class="warning"><strong>Atenção:</strong> <?php echo htmlspecialchars($force_change_reason); ?></p>
        <?php endif; ?>

        <form action="process_change_password.php" method="post" id="changePasswordForm">
            <div>
                <label for="current_password">Senha Atual:</label>
                <input type="password" id="current_password" name="current_password" 
                       autocomplete="current-password"
                       <?php 
                           // Se for primeiro acesso (pwdLastSet=0), desabilita e não exige senha atual.
                           // Esta verificação de 'primeiro acesso' na razão é uma simplificação.
                           // A lógica mais robusta para pwdLastSet=0 estaria no process_change_password.php
                           // para ignorar a validação da senha atual.
                           $is_first_access_scenario = ($force_change_reason && stripos($force_change_reason, 'primeiro acesso') !== false);
                           if ($is_first_access_scenario) {
                               echo 'disabled value="" title="Não é necessário informar a senha atual no primeiro acesso ou reset." ';
                           } else {
                               echo 'required ';
                           }
                       ?>>
                <?php if ($is_first_access_scenario): ?>
                    <small>Não é necessário informar a senha atual neste caso.</small>
                    <input type="hidden" name="current_password_skipped" value="true">
                <?php endif; ?>
            </div>
            <div>
                <label for="new_password">Nova Senha:</label>
                <input type="password" id="new_password" name="new_password" required autocomplete="new-password">
            </div>
            <div>
                <label for="confirm_password">Confirmar Nova Senha:</label>
                <input type="password" id="confirm_password" name="confirm_password" required autocomplete="new-password">
            </div>
            <div id="password_policy_message" class="form-message"></div>
            <div id="password_message" class="form-message"></div>
            <div class="password-requirements">
                <h4>Requisitos da senha:</h4>
                <ul>
                    <li>Mínimo de 14 caracteres.</li>
                    <li>Deve conter letras maiúsculas (A-Z).</li>
                    <li>Deve conter letras minúsculas (a-z).</li>
                    <li>Deve conter números (0-9).</li>
                    <li>Deve conter caracteres especiais (ex: !@#$%^&*).</li>
                </ul>
            </div>
            <button type="submit" id="submit_button" disabled>Alterar Senha</button>
        </form>
        <br>
        <a href="index.php" class="button">Voltar para o Início</a>
    </main>
    <footer>
    <p>&copy; <?php echo date("Y"); ?> Specto Tecnologia - Portal de Senha | Desenvolvido por <a href="https://www.linkedin.com/in/paulo-f-santos/" class="developer-link" target="_blank">Paulo Francisco dos Santos</a></p>
    </footer>
</body>
</html>