<?php
function fetchCsrfAndCookies($initialCookieHeader) {
    $startUrl = "https://sipede.kejaksaan.go.id/login-sso";
    $maxRedirects = 20;
    $timeout = 30;

    $cookieJar = [];

    if (!empty($initialCookieHeader)) {
        $pairs = explode(';', $initialCookieHeader);
        foreach ($pairs as $p) {
            $p = trim($p);
            if ($p === '') continue;
            if (strpos($p, '=') !== false) {
                list($n, $v) = explode('=', $p, 2);
                $cookieJar[trim($n)] = trim($v);
            }
        }
    }

    // ================= helpers =================
    $extractCookiesFromHeaders = function ($headers, &$cookieJar) {
        foreach ($headers as $line) {
            if (stripos($line, 'Set-Cookie:') === 0) {
                $cookieLine = trim(substr($line, strlen('Set-Cookie:')));
                $parts = explode(';', $cookieLine);
                $nameValue = trim($parts[0]);
                if (strpos($nameValue, '=') !== false) {
                    list($name, $value) = explode('=', $nameValue, 2);
                    $cookieJar[trim($name)] = trim($value);
                }
            }
        }
    };

    $buildCookieHeader = function ($cookieJar) {
        $pairs = [];
        foreach ($cookieJar as $k => $v) {
            $pairs[] = $k . '=' . $v;
        }
        return implode('; ', $pairs);
    };

    $resolveUrl = function ($base, $relative) {
        if (parse_url($relative, PHP_URL_SCHEME) != '') return $relative;
        $baseParts = parse_url($base);
        $scheme = $baseParts['scheme'];
        $host = $baseParts['host'];
        $port = isset($baseParts['port']) ? ':' . $baseParts['port'] : '';
        $basePath = isset($baseParts['path']) ? $baseParts['path'] : '/';
        if (substr($relative, 0, 1) === '/') {
            return $scheme . '://' . $host . $port . $relative;
        }
        $dir = preg_replace('#/[^/]*$#', '/', $basePath);
        $abs = $scheme . '://' . $host . $port . $dir . $relative;
        $abs = preg_replace('#(/\.?/)#', '/', $abs);
        while (strpos($abs, '/..') !== false) {
            $abs = preg_replace('#/[^/]+/\\.\\.#', '/', $abs);
        }
        return $abs;
    };

    $findCsrfInHeaders = function ($headers) {
        foreach ($headers as $h) {
            if (stripos($h, 'X-CSRF-TOKEN:') === 0) return trim(substr($h, strlen('X-CSRF-TOKEN:')));
            if (stripos($h, 'x-csrf-token:') === 0) return trim(substr($h, strlen('x-csrf-token:')));
            if (preg_match('/^([\w-]+):\s*(.+)$/', $h, $m)) {
                $name = strtolower($m[1]);
                if ($name === 'x-csrf-token' || $name === 'x-xsrf-token' || $name === 'x-csrf') {
                    return trim($m[2]);
                }
            }
        }
        return null;
    };

    $findCsrfInBody = function ($body) {
        if (preg_match('/<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\'][^>]*>/i', $body, $m)) {
            return $m[1];
        }
        if (preg_match('/<input[^>]*name=["\'](?:_csrf|csrf_token|csrfmiddlewaretoken)["\'][^>]*value=["\']([^"\']+)["\'][^>]*>/i', $body, $m)) {
            return $m[1];
        }
        return null;
    };

    // ================= main flow =================
    $currentUrl = $startUrl;
    $attempt = 0;
    $finalStatus = null;
    $finalBody = null;
    $foundCsrf = null;

    while ($attempt < $maxRedirects) {
        $attempt++;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $currentUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        $cookieHeaderForSend = $buildCookieHeader($cookieJar);
        $headersSend = ['User-Agent: PHP-CSRF-Follower/1.0'];
        if ($cookieHeaderForSend !== '') $headersSend[] = 'Cookie: ' . $cookieHeaderForSend;
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headersSend);

        $response = curl_exec($ch);
        if ($response === false) {
            $err = curl_error($ch);
            curl_close($ch);
            return ['error' => 'cURL error', 'message' => $err];
        }

        $info = curl_getinfo($ch);
        $httpCode = $info['http_code'];
        $headerSize = $info['header_size'];
        $rawHeaders = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);
        $headerLines = preg_split("/\r\n|\n|\r/", trim($rawHeaders));

        $extractCookiesFromHeaders($headerLines, $cookieJar);

        if ($foundCsrf === null) {
            $possible = $findCsrfInHeaders($headerLines);
            if ($possible) $foundCsrf = $possible;
        }

        if ($httpCode === 200) {
            if ($foundCsrf === null) {
                foreach (['XSRF-TOKEN', 'X-CSRF-TOKEN', 'X-CSRF'] as $cname) {
                    if (isset($cookieJar[$cname])) {
                        $foundCsrf = $cookieJar[$cname];
                        break;
                    }
                }
            }
            if ($foundCsrf === null) {
                $maybe = $findCsrfInBody($body);
                if ($maybe) $foundCsrf = $maybe;
            }
            $finalStatus = $httpCode;
            $finalBody = $body;
            curl_close($ch);
            break;
        }

        if ($httpCode >= 300 && $httpCode < 400) {
            $location = null;
            foreach ($headerLines as $h) {
                if (stripos($h, 'Location:') === 0) {
                    $location = trim(substr($h, strlen('Location:')));
                    break;
                }
            }
            if ($location === null) {
                curl_close($ch);
                $finalStatus = $httpCode;
                $finalBody = $body;
                break;
            }
            $currentUrl = $resolveUrl($currentUrl, $location);
            curl_close($ch);
            continue;
        } else {
            if ($foundCsrf === null) {
                foreach (['XSRF-TOKEN', 'X-CSRF-TOKEN', 'X-CSRF'] as $cname) {
                    if (isset($cookieJar[$cname])) {
                        $foundCsrf = $cookieJar[$cname];
                        break;
                    }
                }
            }
            $finalStatus = $httpCode;
            $finalBody = $body;
            curl_close($ch);
            break;
        }
    }

    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    $dom->loadHTML($finalBody);
    libxml_clear_errors();

    $metas = $dom->getElementsByTagName('meta');
    $csrf_token_dom = null;
    foreach ($metas as $meta) {
        if ($meta->getAttribute('name') === 'csrf-token') {
            $csrf_token_dom = $meta->getAttribute('content');
            break;
        }
    }

    $xsrfToken = $cookieJar['XSRF-TOKEN'] ?? null;
    $laravelSession = $cookieJar['laravel_session'] ?? null;

    if ($xsrfToken === null || $laravelSession === null || $csrf_token_dom === null) {
    $httpCodeOutput = 400;
    }

    return [
        'status' => $finalStatus,
        'xsrfToken' => $xsrfToken,
        'laravelSession' => $laravelSession,
        'x_csrf_token' => $csrf_token_dom,
    ];
}

// ===== Example penggunaan =====
// $result = fetchCsrfAndCookies($initialCookieHeader);
// echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
