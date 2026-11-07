<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
header('Content-Type: application/json; charset=utf-8');

const SENTRYIQ_PASSKEY_GCM_NONCE_BYTES = 12;
const SENTRYIQ_PASSKEY_GCM_TAG_BYTES = 16;

function passkey_auth_json(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}

function pk_b64(string $value): string { return rtrim(strtr(base64_encode($value), '+/', '-_'), '='); }
function pk_unb64(string $value): string|false
{
    if ($value === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $value)) return false;
    $pad = strlen($value) % 4;
    if ($pad) $value .= str_repeat('=', 4 - $pad);
    return base64_decode(strtr($value, '-_', '+/'), true);
}
function pk_origin(): array
{
    $configFile = dirname(__DIR__, 2) . '/sentryiq_config.php';
    $config = is_file($configFile) ? require $configFile : [];
    $parts = is_array($config) ? parse_url(trim((string)($config['base_url'] ?? ''))) : false;
    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https' || empty($parts['host'])) throw new RuntimeException('SentryIQ HTTPS origin is unavailable.');
    $host = strtolower((string)$parts['host']);
    if (!preg_match('/^[a-z0-9.-]+$/', $host)) throw new RuntimeException('Invalid SentryIQ relying party identifier.');
    $port = isset($parts['port']) ? ':' . (int)$parts['port'] : '';
    return ['origin' => 'https://' . $host . $port, 'rp_id' => $host];
}
function pk_path(): string
{
    $dataDir = sentryiq_data_dir();
    if ($dataDir === '') throw new RuntimeException('SentryIQ secure data directory is unavailable.');
    return $dataDir . '/passkeys.json';
}
function pk_store(): array
{
    $path = pk_path();
    if (!is_file($path) || is_link($path)) return [];
    $raw = @file_get_contents($path);
    $data = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($data) ? $data : [];
}
function pk_save(array $data): void
{
    $path = pk_path();
    $tmp = $path . '.tmp-' . bin2hex(random_bytes(12));
    $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $handle = @fopen($tmp, 'xb');
    if ($handle === false) throw new RuntimeException('Unable to create secure passkey storage.');
    try {
        @chmod($tmp, 0600);
        if (fwrite($handle, $json) !== strlen($json)) throw new RuntimeException('Unable to write secure passkey storage.');
        fflush($handle);
        if (function_exists('fsync')) @fsync($handle);
    } finally { fclose($handle); }
    if (!@rename($tmp, $path)) { @unlink($tmp); throw new RuntimeException('Unable to activate secure passkey storage.'); }
    @chmod($path, 0600);
}
function pk_visitor_ip(): string
{
    $ip = trim((string)($_SERVER['REMOTE_ADDR'] ?? ''));
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}
function pk_log_security_event(string $eventType, string $ipAddress, ?string $username = null, array $context = []): void
{
    try {
        $dataDir = sentryiq_data_dir();
        if ($dataDir === '') { error_log('SentryIQ security event: ' . $eventType); return; }
        $path = $dataDir . '/security_audit.log';
        $event = ['timestamp'=>date('c'),'event'=>$eventType,'username'=>$username ?? ($_SESSION['app_username'] ?? 'unknown'),'ip'=>$ipAddress,'user_agent'=>$_SERVER['HTTP_USER_AGENT'] ?? 'unknown','context'=>$context];
        $json = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . PHP_EOL;
        @file_put_contents($path, $json, FILE_APPEND | LOCK_EX);
        @chmod($path, 0600);
    } catch (Throwable $exception) { error_log('SentryIQ security event logging failure: ' . $exception->getMessage()); }
}
function pk_validate_client(string $json, string $type, string $challenge, string $origin): void
{
    try { $data = json_decode($json, true, 16, JSON_THROW_ON_ERROR); } catch (Throwable) { throw new RuntimeException('Invalid WebAuthn client data.'); }
    if (!is_array($data) || ($data['type'] ?? '') !== $type || ($data['origin'] ?? '') !== $origin) throw new RuntimeException('WebAuthn client validation failed.');
    if (!is_string($data['challenge'] ?? null) || !hash_equals($challenge, $data['challenge'])) throw new RuntimeException('WebAuthn challenge validation failed.');
    if (($data['crossOrigin'] ?? false) === true) throw new RuntimeException('Cross-origin WebAuthn is not permitted.');
}
function pk_auth_data(string $data, string $rpId, bool $registration): array
{
    if (strlen($data) < 37 || !hash_equals(hash('sha256', $rpId, true), substr($data, 0, 32))) throw new RuntimeException('WebAuthn relying party validation failed.');
    $flags = ord($data[32]);
    if (($flags & 0x01) === 0 || ($flags & 0x04) === 0) throw new RuntimeException('User verification was not performed.');
    $counter = unpack('N', substr($data, 33, 4))[1];
    if (!$registration) {
        if (($flags & 0x40) !== 0) throw new RuntimeException('Invalid WebAuthn assertion data.');
        return ['flags'=>$flags,'counter'=>(int)$counter];
    }
    if (($flags & 0x40) === 0 || strlen($data) < 55) throw new RuntimeException('Passkey credential data is missing.');
    $length = unpack('n', substr($data, 53, 2))[1];
    if ($length < 16 || strlen($data) < 55 + $length) throw new RuntimeException('Invalid passkey credential identifier.');
    return ['flags'=>$flags,'counter'=>(int)$counter,'credential_id'=>substr($data,55,$length)];
}
function pk_wrap(string $masterKey, string $prf, string $salt, string $credentialId): array
{
    if (strlen($masterKey) !== 32 || strlen($prf) !== 32 || strlen($salt) !== 32) throw new RuntimeException('Invalid passkey key material.');
    $key = hash_hkdf('sha256',$prf,32,'SentryIQ passkey vault key',$salt);
    $nonce = random_bytes(SENTRYIQ_PASSKEY_GCM_NONCE_BYTES); $tag = '';
    $cipher = openssl_encrypt($masterKey,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$nonce,$tag,$credentialId,SENTRYIQ_PASSKEY_GCM_TAG_BYTES);
    if ($cipher === false || strlen($tag) !== SENTRYIQ_PASSKEY_GCM_TAG_BYTES) throw new RuntimeException('Unable to protect the vault key with the passkey.');
    return ['nonce'=>pk_b64($nonce),'tag'=>pk_b64($tag),'ciphertext'=>pk_b64($cipher)];
}
function pk_unwrap(array $wrap, string $prf, string $salt, string $credentialId): string|false
{
    $nonce=pk_unb64((string)($wrap['nonce']??'')); $tag=pk_unb64((string)($wrap['tag']??'')); $cipher=pk_unb64((string)($wrap['ciphertext']??''));
    if ($nonce===false||$tag===false||$cipher===false||strlen($nonce)!==SENTRYIQ_PASSKEY_GCM_NONCE_BYTES||strlen($tag)!==SENTRYIQ_PASSKEY_GCM_TAG_BYTES) return false;
    $key=hash_hkdf('sha256',$prf,32,'SentryIQ passkey vault key',$salt);
    $plain=openssl_decrypt($cipher,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$nonce,$tag,$credentialId);
    return is_string($plain)&&strlen($plain)===32?$plain:false;
}
function pk_request_salt(array $store): string
{
    $salt=pk_unb64((string)($store['prf_salt']??''));
    if ($salt!==false&&strlen($salt)===32) return $salt;
    return random_bytes(32);
}

try {
    $origin=pk_origin(); $store=pk_store(); $action=(string)($_GET['action']??'');
    if ($_SERVER['REQUEST_METHOD']==='GET'&&$action==='register-options') {
        sentryiq_require_auth(); $user=trim((string)($_SESSION['app_username']??''));
        if ($user==='') throw new RuntimeException('Authenticated username is unavailable.');
        $challenge=random_bytes(32); $salt=pk_request_salt($store); $_SESSION['pk_register_challenge']=pk_b64($challenge); $_SESSION['pk_register_salt']=pk_b64($salt);
        passkey_auth_json(['status'=>'ok','options'=>['challenge'=>pk_b64($challenge),'rp'=>['id'=>$origin['rp_id'],'name'=>'SentryIQ'],'user'=>['id'=>pk_b64(hash('sha256','sentryiq-user|'.$user,true)),'name'=>$user,'displayName'=>'SentryIQ Vault'],'pubKeyCredParams'=>[['type'=>'public-key','alg'=>-7]],'authenticatorSelection'=>['residentKey'=>'required','requireResidentKey'=>true,'userVerification'=>'required'],'timeout'=>60000,'attestation'=>'none','extensions'=>['prf'=>['eval'=>['first'=>pk_b64($salt)]]]]]);
    }
    if ($_SERVER['REQUEST_METHOD']==='GET'&&$action==='login-options') {
        $salt=pk_unb64((string)($store['prf_salt']??'')); if ($salt===false||strlen($salt)!==32||empty($store['credentials'])||!is_array($store['credentials'])) throw new RuntimeException('No passkey is registered.');
        $challenge=random_bytes(32); $_SESSION['pk_login_challenge']=pk_b64($challenge); passkey_auth_json(['status'=>'ok','options'=>['challenge'=>pk_b64($challenge),'rpId'=>$origin['rp_id'],'userVerification'=>'required','timeout'=>60000,'extensions'=>['prf'=>['eval'=>['first'=>pk_b64($salt)]]]]]);
    }
    if ($_SERVER['REQUEST_METHOD']!=='POST') throw new RuntimeException('POST required.');
    $raw=file_get_contents('php://input'); $request=is_string($raw)?json_decode($raw,true,32,JSON_THROW_ON_ERROR):null; if (!is_array($request)) throw new RuntimeException('Invalid passkey request.');
    $action=(string)($request['action']??'');
    if ($action==='register') {
        sentryiq_require_auth(); $providedCsrf=(string)($request['csrf_token']??''); $expectedCsrf=(string)($_SESSION['csrf_token']??'');
        if ($expectedCsrf===''||$providedCsrf===''||!hash_equals($expectedCsrf,$providedCsrf)) throw new RuntimeException('Security validation failed.');
        $challenge=pk_unb64((string)($_SESSION['pk_register_challenge']??'')); $salt=pk_unb64((string)($_SESSION['pk_register_salt']??'')); if ($challenge===false||strlen($challenge)!==32||$salt===false||strlen($salt)!==32) throw new RuntimeException('Passkey registration session expired.');
        $rawId=pk_unb64((string)($request['rawId']??'')); $clientData=pk_unb64((string)($request['clientDataJSON']??'')); $authData=pk_unb64((string)($request['authenticatorData']??'')); $publicKey=pk_unb64((string)($request['publicKey']??'')); $prf=pk_unb64((string)($request['prf']??''));
        if ($rawId===false||$clientData===false||$authData===false||$publicKey===false||$prf===false||strlen($rawId)<16||strlen($prf)!==32) throw new RuntimeException('Incomplete passkey registration response.');
        pk_validate_client($clientData,'webauthn.create',pk_b64($challenge),$origin['origin']); $auth=pk_auth_data($authData,$origin['rp_id'],true); if (!hash_equals($rawId,$auth['credential_id'])) throw new RuntimeException('Passkey credential identifier mismatch.');
        $key=@openssl_pkey_get_public($publicKey); if ($key===false) throw new RuntimeException('Invalid passkey public key.'); $details=openssl_pkey_get_details($key); if (!is_array($details)||(int)($details['type']??-1)!==OPENSSL_KEYTYPE_EC||($details['ec']['curve_name']??'')!=='prime256v1') throw new RuntimeException('SentryIQ requires an ES256 passkey.');
        $credentialId=pk_b64($rawId); $wrapped=pk_wrap((string)$_SESSION['master_key'],$prf,$salt,$credentialId); $credentials=is_array($store['credentials']??null)?$store['credentials']:[];
        foreach ($credentials as $record) if (is_array($record)&&hash_equals((string)($record['credential_id']??''),$credentialId)) throw new RuntimeException('This passkey is already registered.');
        $credentials[]=['credential_id'=>$credentialId,'public_key'=>pk_b64($publicKey),'username'=>(string)$_SESSION['app_username'],'wrap'=>$wrapped,'sign_count'=>$auth['counter'],'created_at'=>time()];
        pk_save(['version'=>1,'prf_salt'=>pk_b64($salt),'credentials'=>$credentials]); unset($_SESSION['pk_register_challenge'],$_SESSION['pk_register_salt']); pk_log_security_event('PASSKEY_REGISTERED',pk_visitor_ip(),(string)($_SESSION['app_username']??'unknown')); passkey_auth_json(['status'=>'ok']);
    }
    if ($action==='delete') {
        sentryiq_require_auth(); $providedCsrf=(string)($request['csrf_token']??''); $expectedCsrf=(string)($_SESSION['csrf_token']??'');
        if ($expectedCsrf===''||$providedCsrf===''||!hash_equals($expectedCsrf,$providedCsrf)) throw new RuntimeException('Security validation failed.');
        $credentialId=(string)($request['credential_id']??''); if (pk_unb64($credentialId)===false) throw new RuntimeException('Invalid passkey identifier.');
        $credentials=is_array($store['credentials']??null)?$store['credentials']:[]; if (count($credentials)<=1) throw new RuntimeException('The last passkey cannot be removed. Keep at least one passkey registered, or use password recovery.');
        $removed=false; $remaining=[];
        foreach ($credentials as $record) { if (is_array($record)&&hash_equals((string)($record['credential_id']??''),$credentialId)) { $removed=true; continue; } $remaining[]=$record; }
        if (!$removed) throw new RuntimeException('Passkey not found.');
        if ($dataDir = sentryiq_data_dir()) { require_once dirname(__DIR__, 2) . '/cloud/Gallery/Storage/GalleryKeyStore.php'; (new \SentryIQCloud\Gallery\Storage\GalleryKeyStore($dataDir . '/gallery_keys.json'))->removeCredentialEnvelope($credentialId); }
        $store['credentials']=$remaining; pk_save($store); pk_log_security_event('PASSKEY_REMOVED',pk_visitor_ip(),(string)($_SESSION['app_username']??'unknown'),['credential_id'=>$credentialId]); passkey_auth_json(['status'=>'ok']);
    }
    if ($action==='login') {
        $challenge=pk_unb64((string)($_SESSION['pk_login_challenge']??'')); $salt=pk_unb64((string)($store['prf_salt']??'')); if ($challenge===false||strlen($challenge)!==32||$salt===false||strlen($salt)!==32) throw new RuntimeException('Passkey login session expired.');
        $rawId=pk_unb64((string)($request['rawId']??'')); $clientData=pk_unb64((string)($request['clientDataJSON']??'')); $authData=pk_unb64((string)($request['authenticatorData']??'')); $signature=pk_unb64((string)($request['signature']??'')); $prf=pk_unb64((string)($request['prf']??'')); if ($rawId===false||$clientData===false||$authData===false||$signature===false||$prf===false||strlen($prf)!==32) throw new RuntimeException('Incomplete passkey authentication response.');
        pk_validate_client($clientData,'webauthn.get',pk_b64($challenge),$origin['origin']); $auth=pk_auth_data($authData,$origin['rp_id'],false); $id=pk_b64($rawId); $found=null; foreach ((array)($store['credentials']??[]) as $index=>$record) if (is_array($record)&&hash_equals((string)($record['credential_id']??''),$id)) {$found=[$index,$record];break;}
        if ($found===null) throw new RuntimeException('Unknown passkey.'); [$index,$record]=$found; $publicKey=pk_unb64((string)($record['public_key']??'')); if ($publicKey===false) throw new RuntimeException('Stored passkey public key is invalid.'); $key=@openssl_pkey_get_public($publicKey); if ($key===false) throw new RuntimeException('Stored passkey public key is invalid.');
        $clientHash=hash('sha256',$clientData,true); if (openssl_verify($authData.$clientHash,$signature,$key,OPENSSL_ALGO_SHA256)!==1) throw new RuntimeException('Passkey signature verification failed.'); $previous=(int)($record['sign_count']??0); if ($auth['counter']!==0&&$previous!==0&&$auth['counter']<=$previous) throw new RuntimeException('Passkey signature counter validation failed.');
        $masterKey=pk_unwrap((array)($record['wrap']??[]),$prf,$salt,$id); if ($masterKey===false) throw new RuntimeException('Passkey could not unlock the vault.'); $store['credentials'][$index]['sign_count']=max($previous,$auth['counter']); pk_save($store); unset($_SESSION['pk_login_challenge']); sentryiq_mark_authenticated($masterKey,(string)$record['username']); pk_log_security_event('VAULT_LOGIN_PASSKEY',pk_visitor_ip(),(string)$record['username'],['stage'=>'passkey']); passkey_auth_json(['status'=>'ok']);
    }
    throw new RuntimeException('Unknown passkey operation.');
} catch (Throwable $exception) {
    error_log('SentryIQ passkey authentication failure: '.$exception::class.': '.$exception->getMessage());
    passkey_auth_json(['status'=>'error','message'=>$exception->getMessage()],400);
}
