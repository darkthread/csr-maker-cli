param (
    # 網站最主要使用的名稱：機器名稱、網域名稱或 IP
    [Parameter(Mandatory = $true)][string]$HostName,
    # 替代主體名稱(選擇性)，以逗號分隔的字串，例如：proxy.home.net,home.net,192.168.1.1
    $AltSubjectNames,
    $Password,
    [switch]$KeepPlainPrivKey
)
$ErrorActionPreference = "Stop"

# 使用 where openssl 尋找 openssl.exe 的路徑
$opensslPath = & cmd /c "where openssl"
if (!($opensslPath -match "openssl.exe")) {
    # 若找不到，嘗試借用 git 的 openssl.exe
    $gitPath = & cmd /c "where git"
    if ($gitPath -match "git.exe") {
        $opensslPath = Resolve-Path(([IO.Path]::GetDirectoryName($gitPath) + "\..\mingw64\bin\openssl.exe")) -ErrorAction SilentlyContinue
        if (!(Test-Path $opensslPath)) {
            $opensslPath = $null
        }
    }
    if (!($opensslPath -match "openssl.exe")) {
        Write-Host "找不到 openssl.exe，請確保已安裝 OpenSSL 並將其加入系統 PATH 環境變數"
        exit 1
    }
}

$dataRootFolder = (Join-Path $PSScriptRoot "data")
# 若不存在則建立資料夾
if (!(Test-Path $dataRootFolder)) {
    New-Item -ItemType Directory -Path $dataRootFolder | Out-Null
}

Write-Host "準備產生 CSR 檔案..." -ForegroundColor Cyan
Write-Host " - 主要名稱(用於檔名): $HostName"
if ($AltSubjectNames) {
    if ($AltSubjectNames -is [string]) {
        $AltSubjectNames = $AltSubjectNames -split ","
    }
    Write-Host " - 替代主體名稱: $AltSubjectNames"
}
else {
    Write-Host " - 無替代主體名稱"
}

# 用主機名稱當資料夾
$dataFolder = Join-Path $dataRootFolder $HostName
# 若不存在則建立資料夾
if (!(Test-Path $dataFolder)) {
    New-Item -ItemType Directory -Path $dataFolder | Out-Null
}

Write-Host "若確認資料正確請按 Y 鍵繼續，或按其他鍵取消" -ForegroundColor Yellow
$key = [System.Console]::ReadKey($true)
if ($key.KeyChar.ToString().ToUpper() -ne "Y") {
    exit 1
}
if ($Password) {
    $passwdPlain = $Password
}
else {
    Write-Host "請設定一組金鑰保護密碼並記下來，未來製作及匯入憑證時會再用到它" -ForegroundColor Magenta
    while ($true) {
        $passwd = Read-Host "請輸入金鑰保護密碼" -AsSecureString
        $passwdPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwd))
        $passwdConfirm = Read-Host "請再次輸入金鑰保護密碼以確認" -AsSecureString
        if ($passwdPlain -ne [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwdConfirm))) {
            Write-Host "密碼不一致，請重新輸入" -ForegroundColor Red
            continue
        }
        else {
            break
        }
    }
}

$WorkFolder = $dataFolder
$privKeyPath = (Join-Path $WorkFolder "$HostName.privkey")
$confPath = (Join-Path $WorkFolder "$HostName.conf")
$csrPath = (Join-Path $WorkFolder "$HostName.csr")
# 執行 openssl.exe 生成 CSR
Write-Host "產生私鑰檔案 $privKeyPath..." -ForegroundColor Yellow
& $opensslPath genrsa -out $privKeyPath 4096
Write-Host "產生配置檔案 $confPath..." -ForegroundColor Yellow

# 產生 conf 內容
$conf = Get-Content .\csr-conf-template.ini -Raw
$conf = $conf -replace "#HostName", $HostName

$altNames = @($HostName)
if ($AltSubjectNames) {
    $altNames += ($AltSubjectNames -split ",")
}

$ipIdx = 1
$dnsIdx = 1
for ($i = 0; $i -lt $altNames.Length; $i++) {
    if ($altNames[$i] -match "^\d+\.\d+\.\d+\.\d+$") {
        $conf += "`nIP.$($ipIdx)=$($altNames[$i])"
        $ipIdx++
    }
    else {
        $conf += "`nDNS.$($dnsIdx)=$($altNames[$i])"
        $dnsIdx++
    }
}

$conf | Set-Content -Path $confPath -Encoding utf8

# 執行 openssl.exe 生成 CSR
Write-Host "產生 CSR 檔案 $csrPath..." -ForegroundColor Yellow
& $opensslPath req -new -sha256 -nodes -key $privKeyPath -out $csrPath -config $confPath

# 使用密碼加密私鑰
Write-Host "加密私鑰檔案 $privKeyPath.enc..." -ForegroundColor Yellow
& $opensslPath enc -e -aes128 -k $passwdPlain -a -iter 100 -pbkdf2 -in $privKeyPath -out "$privKeyPath.enc"
if (-Not $KeepPlainPrivKey) {
    Remove-Item $privKeyPath
}
