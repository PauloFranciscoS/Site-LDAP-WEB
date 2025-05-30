<?php
// Inclui o config.php para garantir que session_start() seja chamado
// e para manter um padrão, embora para o logout, apenas session_start() e session_destroy()
// sejam estritamente necessários se o config.php não tiver outras lógicas na inicialização
// que afetem o logout.
require_once 'config.php';

// Destruir todas as variáveis de sessão.
$_SESSION = array();

// Se for desejado destruir a sessão completamente, apague também o cookie de sessão.
// Nota: Isso destruirá a sessão, e não apenas os dados da sessão!
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Finalmente, destruir a sessão.
session_destroy();

// Redirecionar para a página de login (index.php) com uma mensagem.
header("Location: index.php?message=" . urlencode("Você foi desconectado com sucesso."));
exit;
?>
