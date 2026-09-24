<?php

// CloudFlare IP Ranges
// ircf.space

$logFile = __DIR__ . '/crawler.log';

function logError(string $message): void {
    global $logFile;
    $line = date('Y-m-d H:i:s') . ' ERROR: ' . $message . PHP_EOL;
    file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
    error_log($line);
}

function getIps(string $raw): array {
    $ips = [];
    // Removed @ suppressor — errors are now visible via logError below
    $fetch = @file_get_contents($raw, false, stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 10,
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
        ],
    ]));

    if ($fetch === false) {
        logError("Failed to fetch IPs from: $raw");
        return $ips;
    }

    if (!empty($fetch)) {
        $ips = preg_split("/[\f\r\n]+/", $fetch);
        // Validate that we got actual IP-like data
        $validCount = 0;
        foreach ($ips as $ip) {
            if (filter_var(trim($ip), FILTER_VALIDATE_IP)) {
                $validCount++;
            }
        }
        if ($validCount < 3) {
            logError("Fetched data from $raw contains only $validCount valid IPs (expected more)");
        }
    }
    return $ips;
}

// Fetch sources sequentially to limit concurrency and avoid overwhelming upstream
$sources = [
    'bashsiz' => 'https://raw.githubusercontent.com/MortezaBashsiz/CFScanner/main/config/cf.local.iplist',
    'safari'  => 'https://raw.githubusercontent.com/SafaSafari/ss-cloud-scanner/main/ips.txt',
    'farid'   => 'https://raw.githubusercontent.com/vfarid/cf-ip-scanner/main/ipv4.txt',
    'ircf'    => 'https://raw.githubusercontent.com/ircfspace/scanner/main/ipv4.list',
];

$newList = [];
$failedSources = [];

foreach ($sources as $name => $url) {
    $ips = getIps($url);
    if (empty($ips)) {
        $failedSources[] = $name;
        continue;
    }
    $newList = array_merge($newList, $ips);
}

if (empty($newList)) {
    $msg = "All IP sources failed. Failed sources: " . implode(', ', $failedSources);
    logError($msg);
    file_put_contents("export.ipv4", "# Error: $msg\n# Failed sources: " . implode(', ', $failedSources) . "\n");
    exit(1);
}

$newList = array_filter($newList, 'strlen');
$newList = array_unique($newList);
natsort($newList);

$generateList = [];
foreach ($newList as $ip) {
    if (empty($ip)) continue;
    $explode = explode("/", $ip);
    if (!isset($explode[0]) || empty($explode[0])) continue;
    $generateList[$explode[0]] = $explode[0] . '/24';
}

$export = '';
foreach ($generateList as $ip) {
    $export .= $ip . "\n";
}

file_put_contents("export.ipv4", $export);
echo "Exported " . count($generateList) . " unique /24 subnets to export.ipv4" . PHP_EOL;

?>
