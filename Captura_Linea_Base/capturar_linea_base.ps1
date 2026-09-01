$ErrorActionPreference = "Stop"

$dir = "C:\Users\Ciber-UNIPAZ\Desktop\Version 4 Ultra\Proyecto-IPS-IDBS-ML\Captura_Linea_Base"
$dumpcap = "C:\Program Files\Wireshark\dumpcap.exe"
$tshark = "C:\Program Files\Wireshark\tshark.exe"
$capinfos = "C:\Program Files\Wireshark\capinfos.exe"

$interface = "7"
$durationSec = 300

$timestamp = Get-Date -Format "HHmm"
$volumeCsv = Join-Path $dir "captura_volumen_${timestamp}.csv"
$pcapng     = Join-Path $dir "captura_5min_${timestamp}.pcapng"
$volumeLog  = Join-Path $dir "volumen_log_errores_${timestamp}.txt"

$culture = [System.Globalization.CultureInfo]::InvariantCulture

Write-Output "Iniciando captura de $durationSec segundos en interfaz Ethernet (7)..."
Write-Output "Timestamp: $timestamp"
Write-Output "CSV: $volumeCsv"
Write-Output "PCAP: $pcapng"

$volumeJob = Start-Job -ScriptBlock {
    param($csv, $log, $secs)
    $start = Get-Date
    $written = 0
    $interfaces = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Ethernet" }
    $adapter = $interfaces | Select-Object -First 1
    if (-not $adapter) {
        "ERROR: adaptador Ethernet no encontrado" | Out-File $log
        return
    }
    $prev = Get-NetAdapterStatistics -Name $adapter.Name
    $prevTime = Get-Date
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("timestamp,rx_bytes_s,tx_bytes_s,rx_pkts_s,tx_pkts_s")
    $prevBytesRx = $prev.ReceivedBytes
    $prevBytesTx = $prev.SentBytes
    $prevPktsRx  = $prev.ReceivedUnicastPackets + $prev.ReceivedMulticastPackets + $prev.ReceivedBroadcastPackets
    $prevPktsTx  = $prev.SentUnicastPackets + $prev.SentMulticastPackets + $prev.SentBroadcastPackets
    while (($(Get-Date) - $start).TotalSeconds -lt $secs) {
        Start-Sleep -Seconds 2
        try {
            $cur = Get-NetAdapterStatistics -Name $adapter.Name
            $curTime = Get-Date
            $dt = ($curTime - $prevTime).TotalSeconds
            if ($dt -le 0) { $dt = 1 }
            $curBytesRx = $cur.ReceivedBytes
            $curBytesTx = $cur.SentBytes
            $curPktsRx  = $cur.ReceivedUnicastPackets + $cur.ReceivedMulticastPackets + $cur.ReceivedBroadcastPackets
            $curPktsTx  = $cur.SentUnicastPackets + $cur.SentMulticastPackets + $cur.SentBroadcastPackets
            $rx = [math]::Max(0, ($curBytesRx - $prevBytesRx) / $dt)
            $tx = [math]::Max(0, ($curBytesTx - $prevBytesTx) / $dt)
            $prx = [math]::Max(0, ($curPktsRx - $prevPktsRx) / $dt)
            $ptx = [math]::Max(0, ($curPktsTx - $prevPktsTx) / $dt)
            $culture = [System.Globalization.CultureInfo]::InvariantCulture
            $ts = $curTime.ToString("yyyy-MM-dd HH:mm:ss.fff")
            $rxS = $rx.ToString("F2", $culture)
            $txS = $tx.ToString("F2", $culture)
            $prxS = $prx.ToString("F2", $culture)
            $ptxS = $ptx.ToString("F2", $culture)
            $lines.Add("$ts,$rxS,$txS,$prxS,$ptxS")
            $prevBytesRx = $curBytesRx; $prevBytesTx = $curBytesTx
            $prevPktsRx = $curPktsRx; $prevPktsTx = $curPktsTx
            $prevTime = $curTime
            if ($written -lt 600) {
                [System.IO.File]::WriteAllLines($csv, $lines)
                $written++
            }
        } catch {
            "ERR $($_.Exception.Message)" | Out-File $log -Append
        }
    }
} -ArgumentList $volumeCsv, $volumeLog, $durationSec

$pcapJob = Start-Job -ScriptBlock {
    param($dumpcap, $interface, $pcapng, $secs)
    & $dumpcap -i $interface -a duration:$secs -w $pcapng
} -ArgumentList $dumpcap, $interface, $pcapng, $durationSec

Write-Output "Jobs iniciados. Esperando $durationSec segundos..."
$volumeJob | Wait-Job -Timeout ($durationSec + 30) | Out-Null
$pcapJob | Wait-Job -Timeout ($durationSec + 30) | Out-Null

Receive-Job $volumeJob
Receive-Job $pcapJob

Remove-Job $volumeJob -Force -ErrorAction SilentlyContinue
Remove-Job $pcapJob -Force -ErrorAction SilentlyContinue

Write-Output "=== CAPTURA COMPLETADA ==="
Write-Output "Archivo volumen: $volumeCsv"
Write-Output "Archivo paquetes: $pcapng"

if (Test-Path $pcapng) {
    $size = (Get-Item $pcapng).Length
    Write-Output "Tamano PCAP: $([math]::Round($size/1MB, 2)) MB"
}
