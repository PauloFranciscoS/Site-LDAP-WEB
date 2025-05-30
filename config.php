<?php
// Inicia a sess�o para todas as p�ginas que inclu�rem este arquivo
session_start();

// =========================================================================
// !!! TESTE TEMPOR�RIO PARA VERIFICA��O DE CERTIFICADO !!!
// ADICIONE ESTA LINHA TEMPORARIAMENTE PARA TESTE SE ESTIVER COM ERRO "Can't contact LDAP server (Code: -1)"
// SE ISSO RESOLVER, VOC� DEVE CONFIGURAR A CONFIAN�A DO CERTIFICADO CORRETAMENTE EM PRODU��O.
putenv('LDAPTLS_REQCERT=never');
// =========================================================================

// =========================================================================
// DEFINI��ES LDAP - !! ATEN��O A ESTAS CONFIGURA��ES !!
// =========================================================================

// Servidores LDAP
define('LDAP_SERVER', 'ldaps://Princiapl');              // MUDE para 'ldaps://'
define('LDAP_SERVER_BACKUP', 'ldaps://Segundario');    // (Se usar backup, tamb�m para 'ldaps://')
define('LDAP_PORT', 636);                               // MUDE a porta para 636 (porta padr�o LDAPS)

// Dom�nio e Base DN
define('LDAP_DOMAIN', 'dominio.com ');                  // Nome de dom�nio (NetBIOS ou FQDN - ex: 'SEU_DOMINIO' ou 'seu_dominio.com')
define('LDAP_BASE_DN', 'DC=dominio,DC=com');           // Base DN para busca de usu�rios (ex: 'DC=seu_dominio,DC=com')

// ==== CREDENCIAIS DO USU�RIO DE SERVI�O LDAP (ADMIN BIND) ====
// !! VERIFIQUE SE ESTES VALORES S�O ID�NTICOS AOS USADOS COM SUCESSO NO LDAPSEARCH !!
define('LDAP_ADMIN_DN', 'CN=Ldap site,OU=GTI,OU=Usuarios,OU=dominio,DC=specto,DC=com');
define('LDAP_ADMIN_PASSWORD', 'sua senha'); // <--- CONFIRA ESTA SENHA CARACTERE POR CARACTERE!

// =========================================================================
// POL�TICA DE SENHA E OUTRAS CONSTANTES
// =========================================================================

// Pol�tica de Senha do Site (para valida��o no cliente e como refer�ncia)
define('PASSWORD_EXPIRES_DAYS', 180); // Senha vence a cada X dias (refer�ncia, o AD que manda)
// Regex: Pelo menos 1 min�scula, 1 mai�scula, 1 n�mero, 1 especial, m�nimo 14 caracteres.
define('PASSWORD_POLICY_REGEX', '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{14,}$/');

// Constantes UserAccountControl (valores decimais)
define('UAC_ACCOUNT_DISABLED', 2);
define('UAC_DONT_EXPIRE_PASSWORD', 65536);
// define('UAC_PASSWORD_EXPIRED_FLAG_NOT_RELEVANT_HERE', 8388608); // Apenas como refer�ncia

// =========================================================================
// FUN��ES AUXILIARES LDAP E DE DATA
// =========================================================================

/**
 * Converte o formato de tempo do Active Directory (intervalos de 100ns desde 1 Jan 1601)
 * para um timestamp Unix.
 * Retorna null se o timestamp do AD for "0" (nunca) ou o valor m�ximo (sem expira��o via este atributo).
 * @param string $adTimestamp Timestamp do AD.
 * @return int|null Unix timestamp ou null.
 */
function convertAdTime($adTimestamp) {
    if (empty($adTimestamp) || $adTimestamp == "0" || $adTimestamp == "9223372036854775807") {
        return null;
    }
    // O valor � em intervalos de 100 nanossegundos. Dividir por 10.000.000 para obter segundos.
    $secsAfterADEpoch = $adTimestamp / 10000000;
    // A �poca do AD (01/01/1601 UTC) est� 11644473600 segundos antes da �poca Unix (01/01/1970 UTC)
    $adToUnixEpochOffset = 11644473600;
    return (int)($secsAfterADEpoch - $adToUnixEpochOffset);
}

/**
 * Formata um timestamp Unix para uma string de data/hora leg�vel.
 * @param int|null $timestamp Unix timestamp.
 * @return string Data formatada ou "N/A".
 */
function formatDate($timestamp) {
    if ($timestamp === null) {
        return "N/A";
    }
    // Formato brasileiro
    return date('d/m/Y H:i:s', $timestamp);
}

/**
 * Conecta ao servidor LDAP usando as credenciais de administrador (servi�o).
 * Tenta o servidor prim�rio e, em caso de falha, o de backup.
 * @return resource|false Retorna o link de conex�o LDAP em sucesso, ou false em falha.
 */
function ldap_connect_admin() {
    $ldap_conn = null;
    $ldap_port_to_use = defined('LDAP_PORT') ? LDAP_PORT : (strpos(LDAP_SERVER, 'ldaps://') === 0 ? 636 : 389);

    // Tenta o prim�rio
    $ldap_conn = @ldap_connect(LDAP_SERVER, $ldap_port_to_use);
    if ($ldap_conn) {
        ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldap_conn, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($ldap_conn, LDAP_OPT_NETWORK_TIMEOUT, 5); // Timeout de 5 segundos
        if (@ldap_bind($ldap_conn, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)) {
            return $ldap_conn; // Sucesso com o prim�rio
        }
        @ldap_close($ldap_conn); // Fecha se o bind falhou
        $ldap_conn = null; // Reseta para tentar o backup
    }

    // Se o prim�rio falhou e existe um backup definido
    if (defined('LDAP_SERVER_BACKUP') && LDAP_SERVER_BACKUP) {
        $ldap_port_backup_to_use = defined('LDAP_PORT') ? LDAP_PORT : (strpos(LDAP_SERVER_BACKUP, 'ldaps://') === 0 ? 636 : 389);
        $ldap_conn = @ldap_connect(LDAP_SERVER_BACKUP, $ldap_port_backup_to_use);
        if ($ldap_conn) {
            ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($ldap_conn, LDAP_OPT_REFERRALS, 0);
            ldap_set_option($ldap_conn, LDAP_OPT_NETWORK_TIMEOUT, 5);
            if (@ldap_bind($ldap_conn, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)) {
                return $ldap_conn; // Sucesso com o backup
            }
            @ldap_close($ldap_conn);
            $ldap_conn = null;
        }
    }
    return false; // Falha em ambos ou nenhum backup definido
}

/**
 * Verifica o status dos servidores LDAP prim�rio e de backup.
 * Tenta conectar e fazer bind usando as credenciais de administrador LDAP.
 *
 * @return array Contendo o status detalhado da conex�o.
 */
function check_ldap_server_status() {
    $status = [
        'primary_server_host' => preg_replace('/^ldap(s?):\/\//i', '', LDAP_SERVER),
        'primary_status' => 'Offline',
        'primary_error' => null,
        'backup_server_host' => (defined('LDAP_SERVER_BACKUP') && LDAP_SERVER_BACKUP) ? preg_replace('/^ldap(s?):\/\//i', '', LDAP_SERVER_BACKUP) : null,
        'backup_status' => (defined('LDAP_SERVER_BACKUP') && LDAP_SERVER_BACKUP) ? 'Offline' : 'N�o Configurado',
        'backup_error' => null,
        'active_connection' => null,
        'connected_to' => 'Nenhum',
        'overall_status' => '?? Inativa' // Corrigido para o emoji vermelho
    ];

    $ldap_port_to_use = defined('LDAP_PORT') ? LDAP_PORT : (strpos(LDAP_SERVER, 'ldaps://') === 0 ? 636 : 389);

    $conn_primary = @ldap_connect(LDAP_SERVER, $ldap_port_to_use);
    if ($conn_primary) {
        ldap_set_option($conn_primary, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($conn_primary, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($conn_primary, LDAP_OPT_NETWORK_TIMEOUT, 5);
        if (@ldap_bind($conn_primary, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)) {
            $status['primary_status'] = 'Online';
            $status['active_connection'] = 'primary';
            $status['connected_to'] = $status['primary_server_host'];
            $status['overall_status'] = '?? Ativa'; // Corrigido para o emoji verde
        } else {
            $status['primary_error'] = "Falha no bind: " . ldap_error($conn_primary) . " (Code: " . ldap_errno($conn_primary) . ")";
        }
        @ldap_close($conn_primary);
    } else {
        $status['primary_error'] = "Falha ao conectar ao servidor (" . LDAP_SERVER . ")";
    }

    if ($status['active_connection'] !== 'primary' && defined('LDAP_SERVER_BACKUP') && LDAP_SERVER_BACKUP) {
        $ldap_port_backup_to_use = defined('LDAP_PORT') ? LDAP_PORT : (strpos(LDAP_SERVER_BACKUP, 'ldaps://') === 0 ? 636 : 389);
        $conn_backup = @ldap_connect(LDAP_SERVER_BACKUP, $ldap_port_backup_to_use);
        if ($conn_backup) {
            ldap_set_option($conn_backup, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($conn_backup, LDAP_OPT_REFERRALS, 0);
            ldap_set_option($conn_backup, LDAP_OPT_NETWORK_TIMEOUT, 5);
            if (@ldap_bind($conn_backup, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)) {
                $status['backup_status'] = 'Online';
                $status['active_connection'] = 'backup';
                $status['connected_to'] = $status['backup_server_host'];
                $status['overall_status'] = '?? Ativa (Backup)'; // Corrigido para o emoji verde
            } else {
                $status['backup_error'] = "Falha no bind: " . ldap_error($conn_backup) . " (Code: " . ldap_errno($conn_backup) . ")";
            }
            @ldap_close($conn_backup);
        } else {
            $status['backup_error'] = "Falha ao conectar ao servidor (" . LDAP_SERVER_BACKUP . ")";
        }
    } elseif ($status['active_connection'] === 'primary' && defined('LDAP_SERVER_BACKUP') && LDAP_SERVER_BACKUP) {
        $ldap_port_backup_to_use = defined('LDAP_PORT') ? LDAP_PORT : (strpos(LDAP_SERVER_BACKUP, 'ldaps://') === 0 ? 636 : 389);
        $conn_backup_check = @ldap_connect(LDAP_SERVER_BACKUP, $ldap_port_backup_to_use);
        if ($conn_backup_check) {
            ldap_set_option($conn_backup_check, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($conn_backup_check, LDAP_OPT_REFERRALS, 0);
            ldap_set_option($conn_backup_check, LDAP_OPT_NETWORK_TIMEOUT, 5);
            if (@ldap_bind($conn_backup_check, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)) {
                $status['backup_status'] = 'Online (Dispon�vel)';
            } else {
                $status['backup_status'] = 'Offline (Falha no Bind)';
                $status['backup_error'] = "Falha no bind: " . ldap_error($conn_backup_check) . " (Code: " . ldap_errno($conn_backup_check) . ")";
            }
            @ldap_close($conn_backup_check);
        } else {
             $status['backup_status'] = 'Offline (Falha na Conex�o)';
             $status['backup_error'] = "Falha ao conectar ao servidor (" . LDAP_SERVER_BACKUP . ")";
        }
    }
    return $status;
}

?>