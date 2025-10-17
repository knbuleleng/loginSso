<?php
header('Content-Type: application/json; charset=utf-8');
require 'get_cookie.php';

$username = $_GET['username'] ?? null;
$password = $_GET['password'] ?? null;

if (!$username) {
    echo json_encode(['error' => 'Parameter username (NIP) wajib diisi']);
    exit;
}

function cleanCookie($cookie) {
    // 1. Hapus tanda kutip ganda di awal/akhir
    $cookie = trim($cookie, '"');

    // 2. Hapus tag HTML yang terselip, misal <br />
    $cookie = preg_replace('/<[^>]*>/', '', $cookie);

    // 3. Hapus spasi berlebih di awal/akhir
    $cookie = trim($cookie);

    return $cookie;
}

// ================= STEP 1: REQUEST KE PORTAL KEJAKSAAN =================
$url1 = "https://portal.kejaksaan.go.id/login-sso?username=" . urlencode($username);
$ch = curl_init($url1);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER => true,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_TIMEOUT => 15,
]);
$response1 = curl_exec($ch);
$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$header1 = substr($response1, 0, $header_size);
curl_close($ch);

// Ambil Set-Cookie
preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $header1, $matches1);
$cookies1 = [];
foreach ($matches1[1] as $item) {
    parse_str($item, $cookie);
    $cookies1 = array_merge($cookies1, $cookie);
}

// Ambil redirect URL
preg_match('/^Location:\s*(.*)$/mi', $header1, $redirectMatch);
$redirect_url = trim($redirectMatch[1] ?? '');

$cookieHeader = '';
foreach ($cookies1 as $k => $v) {
    $cookieHeader .= "$k=$v; ";
}
$cookieHeader = trim($cookieHeader);

// ================= STEP 2: REQUEST KE SSO PORTAL =================
if (!$redirect_url) {
    echo json_encode([
        'status' => 'failed',
        'message' => 'Redirect URL tidak ditemukan dari respon pertama',
        'header1' => $header1
    ], JSON_PRETTY_PRINT);
    exit;
}

$ch = curl_init($redirect_url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER => true,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_HTTPHEADER => [
        "Cookie: $cookieHeader",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ],
]);
$response2 = curl_exec($ch);
$header_size2 = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$header2 = substr($response2, 0, $header_size2);
$body2 = substr($response2, $header_size2);
curl_close($ch);

// Ambil cookies dan action form
preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $header2, $matches2);
$cookies2 = [];
foreach ($matches2[1] as $item) {
    parse_str($item, $cookie);
    $cookies2 = array_merge($cookies2, $cookie);
}
$authSession = $cookies2['AUTH_SESSION_ID'] ?? null;

$action_url = null;
if (preg_match('/<form[^>]+action="([^"]+)"/i', $body2, $matches)) {
    $action_url = html_entity_decode($matches[1], ENT_QUOTES | ENT_HTML5);
}

// Gabung cookies step 1 & 2
$allCookies = array_merge($cookies1, $cookies2);
$cookieHeaderFull = '';
foreach ($allCookies as $k => $v) {
    $cookieHeaderFull .= "$k=$v; ";
}
$cookieHeaderFull = trim($cookieHeaderFull);

// ================= STEP 3: SUBMIT PASSWORD KE ACTION_URL =================
if ($action_url && $authSession) {
    $ch = curl_init($action_url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query(['password' => $password]),
        CURLOPT_HTTPHEADER => [
            "Cookie: $cookieHeaderFull",
            "Content-Type: application/x-www-form-urlencoded",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/*,*/*;q=0.8",
            "Origin: null",
        ],
    ]);
    $response3 = curl_exec($ch);
    $header_size3 = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header3 = substr($response3, 0, $header_size3);
    $body3 = substr($response3, $header_size3);
    curl_close($ch);

    preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $header3, $matches3);
    $cookies3 = [];
    foreach ($matches3[1] as $item) {
        parse_str($item, $cookie);
        $cookies3 = array_merge($cookies3, $cookie);
    }

    preg_match('/^Location:\s*(.*)$/mi', $header3, $locationMatch);
    $callback_url = trim($locationMatch[1] ?? '');

    // ================= STEP 4: CALLBACK KE PORTAL =================
    if ($callback_url) {
        $allCookies = array_merge($allCookies, $cookies3);
        $cookieHeaderFinal = '';
        foreach ($allCookies as $k => $v) {
            $cookieHeaderFinal .= "$k=$v; ";
        }
        $cookieHeaderFinal = trim($cookieHeaderFinal);
        
        // echo $cookieHeaderFinal;

        $ch = curl_init($callback_url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_HTTPHEADER => [
                "Cookie: $cookieHeaderFinal",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            ],
        ]);
        $response4 = curl_exec($ch);
        $header_size4 = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header4 = substr($response4, 0, $header_size4);
        $body4 = substr($response4, $header_size4);
        curl_close($ch);

        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $header4, $matches4);
        $cookies4 = [];
        foreach ($matches4[1] as $item) {
            parse_str($item, $cookie);
            $cookies4 = array_merge($cookies4, $cookie);
        }

        $xsrf = $cookies4['XSRF-TOKEN'] ?? null;
        $session = $cookies4['portal_kejaksaan_agung_republik_indonesia_session'] ?? null;

        // ================= STEP 5: REQUEST KE MYSIMKARI =================
        $mysimkari_url = "https://mysimkari.kejaksaan.go.id/login-sso";
        // Hapus XSRF-TOKEN
        $cookieHeaderFinal_noXSRF = preg_replace('/\b(XSRF-TOKEN|portal_kejaksaan_agung_republik_indonesia_session)=[^;]*;?\s*/', '', $cookieHeaderFinal);
        // echo "baru $cookieHeaderFinal_noXSRF";

        if ($xsrf && $session) {
            $ch = curl_init($mysimkari_url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_TIMEOUT => 15,
                CURLOPT_HTTPHEADER => [
                    "Cookie: XSRF-TOKEN=$xsrf; portal_kejaksaan_agung_republik_indonesia_session=$session; $cookieHeaderFinal_noXSRF",
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                ],
            ]);

            $response5 = curl_exec($ch);
            $header_size5 = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $header5 = substr($response5, 0, $header_size5);
            $body5 = substr($response5, $header_size5);
            curl_close($ch);

            preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $header5, $matches5);
            $cookies5 = [];
            foreach ($matches5[1] as $item) {
                parse_str($item, $cookie);
                $cookies5 = array_merge($cookies5, $cookie);
            }

            $allCookiesFinal = array_merge($cookies4, $cookies5);

            // echo json_encode([
            //     'status' => 'mysimkari_access_success',
            //     'nip' => $username,
            //     'cookies_mysimkari' => $cookies5,
            //     'all_cookies_final' => $allCookiesFinal,
            //     'header_mysimkari' => $header5,
            //     'body_preview' => substr($body5, 0, 500)
            // ], JSON_PRETTY_PRINT);
    
            // 1. Ambil Location
            $location = null;
            if (preg_match("/\r\nLocation:\s*(.+?)\r\n/si", $header5, $m)) {
                $location = trim($m[1]);
            }

            // 2. Ambil semua Set-Cookie (nama => nilai)
            $cookies = [];
            if (preg_match_all("/Set-Cookie:\s*([^=;]+)=([^;]+);/i", $header5, $mc, PREG_SET_ORDER)) {
                foreach ($mc as $c) {
                    $name = trim($c[1]);
                    $value = trim($c[2]);
                    $cookies[$name] = $value;
                }
            }

            // 3. Buat header Cookie: untuk request selanjutnya (gabungkan nama=nilai; ...)
            $cookieHeader = '';
            if (!empty($cookies)) {
                $pairs = [];
                foreach ($cookies as $k => $v) {
                    $pairs[] = $k . '=' . $v;
                }
                $cookieHeader = implode('; ', $pairs);
            }

            // hapus XSRF-TOKEN
            $cookieHeaderForMysimkari = preg_replace('/XSRF-TOKEN=[^;]+; ?/', '', $cookieHeaderFinal);

            // Gabungkan dua cookie
            $cookieCombinedForMysimkari = $cookieHeader . '; ' . $cookieHeaderForMysimkari;

            // Hilangkan spasi ganda atau ; berlebih
            $cookieCleanForMysimkari = trim(preg_replace('/;;+/', ';', $cookieCombinedForMysimkari), '; ');
            
            // ================= STEP 6: REQUEST KE MYSIMKARI_WITH_SSO =================
            $ch = curl_init($location);
            curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_HTTPHEADER => [
                "Cookie: $cookieCleanForMysimkari",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                ],
            ]);

            $response6 = curl_exec($ch);
            $header_size6 = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $header6 = substr($response6, 0, $header_size6);
            $body6 = substr($response6, $header_size6);
            
            // echo $header6;
            $cookiePairs = [];
            if (preg_match_all('/^Set-Cookie:\s*(.+)$/mi', $header6, $cookieMatches)) {
                foreach ($cookieMatches[1] as $cookieLine) {
                    // Ambil nama=value dari awal baris hingga sebelum first ';' (jika ada)
                    if (preg_match('/^\s*([^;]+)/', $cookieLine, $m)) {
                        // m[1] berisi "NAME=VALUE" (bisa saja VALUE mengandung tanda kutip)
                        $nv = trim($m[1]);
                        // Beberapa Set-Cookie berisi KEYCLOAK_SESSION="master/..", hapus tanda kutip di value agar kompatibel header Cookie
                        $nv = preg_replace('/^([^=]+=)"?(.*)"?$/', '$1$2', $nv);
                        // skip empty or expired cookies like "KC_RESTART=" (nilai kosong) if you still want include, leave it
                        // kita tetap masukkan (user mungkin ingin mengirim KC_RESTART=;)
                        $cookiePairs[] = $nv;
                    }
                }
            }

            // Gabungkan menjadi satu string cookie (format header Cookie)
            $allCookiesHeader = implode('; ', $cookiePairs);

            // --- ambil Location (jika ada) ---
            $location_mysimkari = null;
            if (preg_match('/^Location:\s*(.+)$/mi', $header6, $locMatch)) {
                $location_mysimkari = trim($locMatch[1]);
            }

            // echo "cokie $allCookiesHeader";
            $result_final_cookie = fetchCsrfAndCookies(cleanCookie($allCookiesHeader));
            
            echo json_encode($result_final_cookie, JSON_PRETTY_PRINT);
            exit;
        }

        echo json_encode([
            'status' => '400',
            'nip' => $username,
            'message' => 'Token XSRF atau session tidak ditemukan'
        ], JSON_PRETTY_PRINT);
        exit;
    }

    echo json_encode([
        'status' => '400',
        'nip' => $username,
        'raw_header_response' => $header3
    ], JSON_PRETTY_PRINT);
    exit;
}

echo json_encode([
    'status' => '400',
    'nip' => $username,
    'AUTH_SESSION_ID' => $authSession,
    'redirect_url' => $redirect_url,
    'header_sso' => $header2
], JSON_PRETTY_PRINT);
