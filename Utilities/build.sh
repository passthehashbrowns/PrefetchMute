python3 ConvertToShellcode.py ../PrefetchMuteHook/x64/Release/PrefetchMute.dll
mv ../PrefetchMuteHook/x64/Release/PrefetchMute.bin .
base64 -w 0 PrefetchMute.bin > PrefetchMute.b64
echo "Wrote base64 shellcode to: PrefetchMute.b64"
