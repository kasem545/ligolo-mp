<#
.SYNOPSIS
    Ligolo-MP PowerShell Agent
.DESCRIPTION
    Pure PowerShell agent for Ligolo-MP. No server changes required.
    Implements yamux multiplexing and Gob serialization via inline C#.
.PARAMETER Server
    Server address to connect to (dial-out), e.g. "10.0.0.5:11601"
.PARAMETER Bind
    Address to listen on (bind mode), e.g. "0.0.0.0:4444"
.PARAMETER CACertFile
    Path to the CA certificate PEM file
.PARAMETER CertFile
    Path to the agent certificate PEM file (PS 7+ only)
.PARAMETER KeyFile
    Path to the agent private key PEM file (PS 7+ only)
.PARAMETER PfxFile
    Path to a PFX bundle (PS 5.1 compatible)
.PARAMETER PfxPassword
    Password for the PFX file
.PARAMETER Insecure
    Skip TLS certificate verification
.EXAMPLE
    .\agent.ps1 -Server 10.0.0.5:11601 -CACertFile ca.pem -PfxFile agent.pfx
.EXAMPLE
    .\agent.ps1 -Bind 0.0.0.0:4444 -CACertFile ca.pem -PfxFile agent.pfx
#>

param(
    [string]$Bind,
    [string]$Server,
    [Parameter(Mandatory = $true, ParameterSetName = "Cert")]
    [string]$CACertFile,
    [Parameter(ParameterSetName = "PEM")]
    [string]$CertFile,
    [Parameter(ParameterSetName = "PEM")]
    [string]$KeyFile,
    [Parameter(ParameterSetName = "PFX")]
    [string]$PfxFile,
    [Parameter()]
    [string]$PfxPassword = "",
    [switch]$Insecure,
    [Parameter(ParameterSetName = "Help")]
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Ligolo-MP PowerShell Agent

Usage:
  .\agent.ps1 -Server <host:port> -CACertFile <path> -PfxFile <path>
  .\agent.ps1 -Bind  <addr:port> -CACertFile <path> -PfxFile <path>

Options:
  -Server       Server address to connect to (dial-out)
                  Example: -Server 10.0.0.5:11601
  -Bind         Address to listen on (bind mode, server connects to you)
                  Example: -Bind 0.0.0.0:4444
  -CACertFile   Path to CA certificate PEM file (required)
  -PfxFile      Path to PFX bundle (PS 5.1 compatible)
  -PfxPassword  Password for PFX file (default: empty)
  -CertFile     Path to agent cert PEM (PS 7+ only)
  -KeyFile      Path to agent key PEM (PS 7+ only)
  -Insecure     Skip TLS certificate verification
  -Help         Show this help

Examples:
  .\agent.ps1 -Server 10.0.0.5:11601 -CACertFile ca.pem -PfxFile agent.pfx
  .\agent.ps1 -Bind 0.0.0.0:4444 -CACertFile ca.pem -PfxFile agent.pfx
  .\agent.ps1 -Server 10.0.0.5:11601 -CACertFile ca.pem -CertFile agent.pem -KeyFile agent.key
"@
    exit 0
}

if (-not $Bind -and -not $Server) {
    Write-Host "[-] Specify either -Server (dial-out) or -Bind (listen)" -ForegroundColor Red
    Write-Host "[-] Run .\agent.ps1 -Help for usage" -ForegroundColor Yellow
    exit 1
}

$null = Register-EngineEvent PowerShell.Exiting -Action {
    Write-Host "`n[*] Shutting down..." -ForegroundColor Yellow
}

$CSharpCode = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace LigoloProto {

public static class Gob {
    public static void EncodeUint(List<byte> buf, ulong x) {
        if (x <= 0x7F) { buf.Add((byte)x); return; }
        byte[] tmp = new byte[8];
        for (int i = 7; i >= 0; i--) { tmp[i] = (byte)(x & 0xFF); x >>= 8; }
        int lz = 0;
        while (lz < 8 && tmp[lz] == 0) lz++;
        int nBytes = 8 - lz;
        buf.Add((byte)(-(sbyte)nBytes));
        for (int i = lz; i < 8; i++) buf.Add(tmp[i]);
    }

    public static ulong DecodeUint(byte[] data, ref int offset) {
        byte b = data[offset++];
        if (b <= 0x7F) return (ulong)b;
        int n = -(sbyte)b; if (n > 8) n = 8;
        ulong x = 0;
        for (int i = 0; i < n; i++) x = (x << 8) | data[offset++];
        return x;
    }

    public static void EncodeInt(List<byte> buf, long val) {
        ulong x = val < 0 ? (ulong)(~val << 1) | 1u : (ulong)(val << 1);
        EncodeUint(buf, x);
    }

    public static long DecodeInt(byte[] data, ref int offset) {
        ulong x = DecodeUint(data, ref offset);
        return (x & 1) != 0 ? ~(long)(x >> 1) : (long)(x >> 1);
    }

    public static void EncodeString(List<byte> buf, string s) {
        byte[] b = System.Text.Encoding.UTF8.GetBytes(s);
        EncodeUint(buf, (ulong)b.Length);
        buf.AddRange(b);
    }

    public static string DecodeString(byte[] data, ref int offset) {
        ulong len = DecodeUint(data, ref offset);
        string s = System.Text.Encoding.UTF8.GetString(data, offset, (int)len);
        offset += (int)len;
        return s;
    }

    public static void EncodeBool(List<byte> buf, bool v) { EncodeUint(buf, v ? 1UL : 0UL); }
    public static bool DecodeBool(byte[] data, ref int offset) { return DecodeUint(data, ref offset) != 0; }

    public static byte[] BuildGobStream(byte[] typeDefsWithCounts, byte[] valueBytes) {
        List<byte> result = new List<byte>();
        result.AddRange(typeDefsWithCounts);
        EncodeUint(result, (ulong)valueBytes.Length);
        result.AddRange(valueBytes);
        return result.ToArray();
    }
}

public class NetInterfaceData {
    public int Index;
    public int MTU;
    public string Name = "";
    public string HardwareAddr = "";
    public int Flags;
    public List<string> Addresses = new List<string>();
}

public class RedirectorData {
    public string ID = "";
    public string Network = "";
    public string From = "";
    public string To = "";
}

public static class TypeDefs {
    public static readonly byte[] InfoRequest = Hex(
        "1c7f03010111496e666f526571756573745061636b657401ff80000000");

    public static readonly byte[] InfoReply = Hex(
        "54ff810301010f496e666f5265706c795061636b657401ff8200010401044e616d65010c0001" +
        "08486f73746e616d65010c00010a496e746572666163657301ff8800010b5265646972656374" +
        "6f727301ff8c00000026ff87020101175b5d70726f746f636f6c2e4e6574496e746572666163" +
        "6501ff880001ff8400005fff830301010c4e6574496e7465726661636501ff84000106010549" +
        "6e64657801040001034d545501040001044e616d65010c00010c486172647761726541646472" +
        "010a000105466c616773010600010941646472657373657301ff8600000016ff85020101085b" +
        "5d737472696e6701ff8600010c00002dff8b0201011e5b5d70726f746f636f6c2e5265646972" +
        "6563746f72496e7465726661636501ff8c0001ff8a000044ff89030101135265646972656374" +
        "6f72496e7465726661636501ff8a00010401024944010c0001074e6574776f726b010c000104" +
        "46726f6d010c000102546f010c000000");

    public static readonly byte[] ConnectRequest = Hex(
        "4dff8d03010114436f6e6e656374526571756573745061636b657401ff8e00010401034e6574" +
        "01060001095472616e73706f7274010600010741646472657373010c000104506f7274010600" +
        "0000");

    public static readonly byte[] ConnectResponse = Hex(
        "3dff8f03010115436f6e6e656374526573706f6e73655061636b657401ff90000102010b4573" +
        "7461626c6973686564010200010552657365740102000000");

    public static readonly byte[] HostPingRequest = Hex(
        "2fff9103010115486f737450696e67526571756573745061636b657401ff9200010101074164" +
        "6472657373010c000000");

    public static readonly byte[] HostPingResponse = Hex(
        "2eff9303010116486f737450696e67526573706f6e73655061636b657401ff94000101010541" +
        "6c6976650102000000");

    public static readonly byte[] RedirectorRequest = Hex(
        "48ff950301011752656469726563746f72526571756573745061636b657401ff960001040102" +
        "4944010c0001074e6574776f726b010c00010446726f6d010c000102546f010c000000");

    public static readonly byte[] RedirectorResponse = Hex(
        "43ff970301011852656469726563746f72526573706f6e73655061636b657401ff9800010301" +
        "024944010c0001034572720102000109457272537472696e67010c000000");

    public static readonly byte[] RedirectorCloseRequest = Hex(
        "31ff990301011c52656469726563746f72436c6f7365526571756573745061636b657401ff9a" +
        "00010101024944010c000000");

    public static readonly byte[] RedirectorCloseResponse = Hex(
        "41ff9b0301011d52656469726563746f72436c6f7365526573706f6e73655061636b657401ff" +
        "9c0001020109457272537472696e67010c0001034572720102000000");

    public static readonly byte[] DisconnectRequest = Hex(
        "23ff9d03010117446973636f6e6e656374526571756573745061636b657401ff9e000000");

    public static readonly byte[] DisconnectResponse = Hex(
        "24ff9f03010118446973636f6e6e656374526573706f6e73655061636b657401ffa0000000");

    public static byte[] Hex(string hex) {
        hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "").Replace("\t", "");
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }
}

public static class GobEncoder {

    public static long ExtractTypeId(byte[] typeDefsWithCounts) {
        int offset = 0;
        Gob.DecodeUint(typeDefsWithCounts, ref offset);
        long negTypeId = Gob.DecodeInt(typeDefsWithCounts, ref offset);
        return -negTypeId;
    }

    public static byte[] EncodeConnectResponse(bool established, bool reset) {
        long typeId = ExtractTypeId(TypeDefs.ConnectResponse);
        List<byte> val = new List<byte>();
        Gob.EncodeInt(val, typeId);
        int fn = 0;
        if (established) { Gob.EncodeUint(val, (ulong)(1 - fn)); fn = 1; Gob.EncodeBool(val, true); }
        if (reset)       { Gob.EncodeUint(val, (ulong)(2 - fn)); fn = 2; Gob.EncodeBool(val, true); }
        Gob.EncodeUint(val, 0);
        return val.ToArray();
    }

    public static byte[] EncodeHostPingResponse(bool alive) {
        long typeId = ExtractTypeId(TypeDefs.HostPingResponse);
        List<byte> val = new List<byte>();
        Gob.EncodeInt(val, typeId);
        if (alive) { Gob.EncodeUint(val, 1); Gob.EncodeBool(val, true); }
        Gob.EncodeUint(val, 0);
        return val.ToArray();
    }

    public static byte[] EncodeDisconnectResponse() {
        long typeId = ExtractTypeId(TypeDefs.DisconnectResponse);
        List<byte> val = new List<byte>();
        Gob.EncodeInt(val, typeId);
        Gob.EncodeUint(val, 0);
        return val.ToArray();
    }

    public static byte[] EncodeRedirectorResponse(string id, bool err, string errString) {
        long typeId = ExtractTypeId(TypeDefs.RedirectorResponse);
        List<byte> val = new List<byte>();
        Gob.EncodeInt(val, typeId);
        int fn = 0;
        Gob.EncodeUint(val, (ulong)(1 - fn)); fn = 1; Gob.EncodeString(val, id ?? "");
        if (err) { Gob.EncodeUint(val, (ulong)(2 - fn)); fn = 2; Gob.EncodeBool(val, true); }
        if (!string.IsNullOrEmpty(errString)) { Gob.EncodeUint(val, (ulong)(3 - fn)); fn = 3; Gob.EncodeString(val, errString); }
        Gob.EncodeUint(val, 0);
        return val.ToArray();
    }

    public static byte[] EncodeRedirectorCloseResponse(string errString, bool err) {
        long typeId = ExtractTypeId(TypeDefs.RedirectorCloseResponse);
        List<byte> val = new List<byte>();
        Gob.EncodeInt(val, typeId);
        int fn = 0;
        if (!string.IsNullOrEmpty(errString)) { Gob.EncodeUint(val, (ulong)(1 - fn)); fn = 1; Gob.EncodeString(val, errString); }
        if (err) { Gob.EncodeUint(val, (ulong)(2 - fn)); fn = 2; Gob.EncodeBool(val, true); }
        Gob.EncodeUint(val, 0);
        return val.ToArray();
    }

    public static byte[] EncodeInfoReply(string name, string hostname,
                                          List<NetInterfaceData> ifaces,
                                          List<RedirectorData> redirectors) {
        long typeId = ExtractTypeId(TypeDefs.InfoReply);
        List<byte> val = new List<byte>();
        Gob.EncodeInt(val, typeId);
        int fn = 0;

        Gob.EncodeUint(val, (ulong)(1 - fn)); fn = 1; Gob.EncodeString(val, name ?? "");
        Gob.EncodeUint(val, (ulong)(2 - fn)); fn = 2; Gob.EncodeString(val, hostname ?? "");

        Gob.EncodeUint(val, (ulong)(3 - fn)); fn = 3;
        Gob.EncodeUint(val, (ulong)ifaces.Count);
        foreach (var iface in ifaces) {
            int sf = 0;
            if (iface.Index != 0) { Gob.EncodeUint(val, (ulong)(1 - sf)); sf = 1; Gob.EncodeInt(val, iface.Index); }
            if (iface.MTU != 0)   { Gob.EncodeUint(val, (ulong)(2 - sf)); sf = 2; Gob.EncodeInt(val, iface.MTU); }
            if (!string.IsNullOrEmpty(iface.Name)) { Gob.EncodeUint(val, (ulong)(3 - sf)); sf = 3; Gob.EncodeString(val, iface.Name); }
            if (!string.IsNullOrEmpty(iface.HardwareAddr)) {
                Gob.EncodeUint(val, (ulong)(4 - sf)); sf = 4;
                byte[] mac = ParseMac(iface.HardwareAddr);
                Gob.EncodeUint(val, (ulong)mac.Length);
                val.AddRange(mac);
            }
            if (iface.Flags != 0) { Gob.EncodeUint(val, (ulong)(5 - sf)); sf = 5; Gob.EncodeInt(val, iface.Flags); }
            if (iface.Addresses.Count > 0) {
                Gob.EncodeUint(val, (ulong)(6 - sf)); sf = 6;
                Gob.EncodeUint(val, (ulong)iface.Addresses.Count);
                foreach (var addr in iface.Addresses) Gob.EncodeString(val, addr ?? "");
            }
            Gob.EncodeUint(val, 0);
        }

        Gob.EncodeUint(val, (ulong)(4 - fn)); fn = 4;
        Gob.EncodeUint(val, (ulong)redirectors.Count);
        foreach (var r in redirectors) {
            int sf = 0;
            if (!string.IsNullOrEmpty(r.ID))       { Gob.EncodeUint(val, (ulong)(1 - sf)); sf = 1; Gob.EncodeString(val, r.ID); }
            if (!string.IsNullOrEmpty(r.Network))   { Gob.EncodeUint(val, (ulong)(2 - sf)); sf = 2; Gob.EncodeString(val, r.Network); }
            if (!string.IsNullOrEmpty(r.From))      { Gob.EncodeUint(val, (ulong)(3 - sf)); sf = 3; Gob.EncodeString(val, r.From); }
            if (!string.IsNullOrEmpty(r.To))        { Gob.EncodeUint(val, (ulong)(4 - sf)); sf = 4; Gob.EncodeString(val, r.To); }
            Gob.EncodeUint(val, 0);
        }

        Gob.EncodeUint(val, 0);
        return val.ToArray();
    }

    private static byte[] ParseMac(string mac) {
        string[] parts = mac.Split(':', '-');
        byte[] result = new byte[parts.Length];
        for (int i = 0; i < parts.Length; i++)
            result[i] = Convert.ToByte(parts[i], 16);
        return result;
    }
}

public static class GobDecoder {
    public static byte[] ExtractValueMessage(byte[] gobData) {
        int offset = 0;
        int lastMsgOffset = 0;
        while (offset < gobData.Length) {
            ulong msgLen = Gob.DecodeUint(gobData, ref offset);
            lastMsgOffset = offset;
            offset += (int)msgLen;
        }
        if (lastMsgOffset >= gobData.Length) return null;
        int valLen = gobData.Length - lastMsgOffset;
        byte[] result = new byte[valLen];
        Array.Copy(gobData, lastMsgOffset, result, 0, valLen);
        return result;
    }

    public static void DecodeConnectRequest(byte[] valueMsg,
        out byte net, out byte transport, out string address, out ushort port) {
        int offset = 0;
        Gob.DecodeInt(valueMsg, ref offset);
        int fn = 0; net = 0; transport = 0; address = ""; port = 0;
        while (offset < valueMsg.Length) {
            ulong delta = Gob.DecodeUint(valueMsg, ref offset);
            if (delta == 0) break;
            fn += (int)delta;
            switch (fn) {
                case 1: net = (byte)Gob.DecodeUint(valueMsg, ref offset); break;
                case 2: transport = (byte)Gob.DecodeUint(valueMsg, ref offset); break;
                case 3: address = Gob.DecodeString(valueMsg, ref offset); break;
                case 4: port = (ushort)Gob.DecodeUint(valueMsg, ref offset); break;
            }
        }
    }

    public static string DecodeHostPingRequest(byte[] valueMsg) {
        int offset = 0;
        Gob.DecodeInt(valueMsg, ref offset);
        int fn = 0; string address = "";
        while (offset < valueMsg.Length) {
            ulong delta = Gob.DecodeUint(valueMsg, ref offset);
            if (delta == 0) break;
            fn += (int)delta;
            if (fn == 1) address = Gob.DecodeString(valueMsg, ref offset);
        }
        return address;
    }

    public static void DecodeRedirectorRequest(byte[] valueMsg,
        out string id, out string network, out string from, out string to) {
        int offset = 0;
        Gob.DecodeInt(valueMsg, ref offset);
        int fn = 0; id = ""; network = ""; from = ""; to = "";
        while (offset < valueMsg.Length) {
            ulong delta = Gob.DecodeUint(valueMsg, ref offset);
            if (delta == 0) break;
            fn += (int)delta;
            switch (fn) {
                case 1: id = Gob.DecodeString(valueMsg, ref offset); break;
                case 2: network = Gob.DecodeString(valueMsg, ref offset); break;
                case 3: from = Gob.DecodeString(valueMsg, ref offset); break;
                case 4: to = Gob.DecodeString(valueMsg, ref offset); break;
            }
        }
    }

    public static string DecodeRedirectorCloseRequest(byte[] valueMsg) {
        int offset = 0;
        Gob.DecodeInt(valueMsg, ref offset);
        int fn = 0; string id = "";
        while (offset < valueMsg.Length) {
            ulong delta = Gob.DecodeUint(valueMsg, ref offset);
            if (delta == 0) break;
            fn += (int)delta;
            if (fn == 1) id = Gob.DecodeString(valueMsg, ref offset);
        }
        return id;
    }
}

public class YamuxStream : Stream {
    public uint StreamID;
    private BlockingCollection<byte[]> _queue = new BlockingCollection<byte[]>();
    private YamuxServer _server;
    private bool _closed;
    private byte[] _leftover;
    private int _leftoverOffset;

    public YamuxStream(YamuxServer srv, uint id) {
        _server = srv; StreamID = id; _closed = false;
    }

    public void FeedData(byte[] data) { _queue.Add(data); }
    public void SignalClose() { _closed = true; _queue.CompleteAdding(); }

    public override int Read(byte[] buffer, int offset, int count) {
        if (_leftover != null && _leftoverOffset < _leftover.Length) {
            int avail = _leftover.Length - _leftoverOffset;
            int toCopy = Math.Min(count, avail);
            Array.Copy(_leftover, _leftoverOffset, buffer, offset, toCopy);
            _leftoverOffset += toCopy;
            if (_leftoverOffset >= _leftover.Length) { _leftover = null; }
            return toCopy;
        }

        byte[] chunk;
        if (!_queue.TryTake(out chunk, Timeout.Infinite))
            return 0;

        int copy = Math.Min(count, chunk.Length);
        Array.Copy(chunk, 0, buffer, offset, copy);

        if (copy < chunk.Length) {
            _leftover = chunk;
            _leftoverOffset = copy;
        }
        return copy;
    }

    public override void Write(byte[] buffer, int offset, int count) {
        byte[] payload = new byte[count];
        Array.Copy(buffer, offset, payload, 0, count);
        _server.SendData(StreamID, payload);
    }

    public override void Flush() {}
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position {
        get { throw new NotSupportedException(); }
        set { throw new NotSupportedException(); }
    }
    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return true; } }
    public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
    public override void SetLength(long value) { throw new NotSupportedException(); }

    public void CloseStream() {
        if (!_closed) { _server.SendFin(StreamID); _closed = true; }
    }
}

public class YamuxServer {
    private Stream _stream;
    private Dictionary<uint, YamuxStream> _streams = new Dictionary<uint, YamuxStream>();
    private object _lock = new object();
    private BlockingCollection<YamuxStream> _acceptQueue = new BlockingCollection<YamuxStream>();
    private Thread _recvThread;
    private volatile bool _running = true;

    private const byte PROTO_VERSION = 0;
    private const byte TYPE_DATA = 0;
    private const byte TYPE_WINDOW_UPDATE = 1;
    private const byte TYPE_PING = 2;
    private const byte TYPE_GO_AWAY = 3;
    private const ushort FLAG_SYN = 1;
    private const ushort FLAG_ACK = 2;
    private const ushort FLAG_FIN = 4;
    private const ushort FLAG_RST = 8;
    private const int HEADER_SIZE = 12;
    private const uint INITIAL_WINDOW = 256 * 1024;

    public bool IsRunning { get { return _running; } }

    public YamuxServer(Stream underlyingStream) {
        _stream = underlyingStream;
        _recvThread = new Thread(RecvLoop) { IsBackground = true };
        _recvThread.Start();
    }

    public YamuxStream AcceptStream() {
        try { return _acceptQueue.Take(); }
        catch { return null; }
    }

    private void RecvLoop() {
        byte[] header = new byte[HEADER_SIZE];
        try {
            while (_running) {
                if (!ReadExact(header, HEADER_SIZE)) break;

                byte version = header[0];
                byte msgType = header[1];
                ushort flags = (ushort)((header[2] << 8) | header[3]);
                uint streamID = ((uint)header[4] << 24) | ((uint)header[5] << 16) |
                                ((uint)header[6] << 8) | header[7];
                uint length = ((uint)header[8] << 24) | ((uint)header[9] << 16) |
                              ((uint)header[10] << 8) | header[11];

                if (version != PROTO_VERSION) break;

                switch (msgType) {
                    case TYPE_PING:
                        if ((flags & FLAG_SYN) != 0) SendPingAck(length);
                        break;
                    case TYPE_DATA:
                        HandleData(streamID, flags, length);
                        break;
                    case TYPE_WINDOW_UPDATE:
                        HandleWindowUpdate(streamID, flags);
                        break;
                    case TYPE_GO_AWAY:
                        _running = false;
                        break;
                }
            }
        } catch {
        } finally {
            _running = false;
            _acceptQueue.CompleteAdding();
            lock (_lock) { foreach (var s in _streams.Values) s.SignalClose(); }
        }
    }

    private void HandleData(uint streamID, ushort flags, uint length) {
        byte[] payload = null;
        if (length > 0) {
            payload = new byte[length];
            if (!ReadExact(payload, (int)length)) return;
        }

        bool isNew = (flags & FLAG_SYN) != 0;
        bool hasFIN = (flags & FLAG_FIN) != 0;
        bool hasRST = (flags & FLAG_RST) != 0;

        lock (_lock) {
            if (isNew) {
                var s = new YamuxStream(this, streamID);
                _streams[streamID] = s;
                SendWindowUpdate(streamID, FLAG_ACK, INITIAL_WINDOW);
                try { _acceptQueue.Add(s); } catch {}
            }
            if (_streams.ContainsKey(streamID)) {
                var s = _streams[streamID];
                if (payload != null && payload.Length > 0) s.FeedData(payload);
                if (hasFIN || hasRST) { s.SignalClose(); if (hasRST) _streams.Remove(streamID); }
            }
        }
    }

    private void HandleWindowUpdate(uint streamID, ushort flags) {
        bool isNew = (flags & FLAG_SYN) != 0;
        bool hasRST = (flags & FLAG_RST) != 0;

        if (hasRST) {
            lock (_lock) {
                if (_streams.ContainsKey(streamID)) { _streams[streamID].SignalClose(); _streams.Remove(streamID); }
            }
            return;
        }

        if (isNew) {
            lock (_lock) {
                if (!_streams.ContainsKey(streamID)) {
                    var s = new YamuxStream(this, streamID);
                    _streams[streamID] = s;
                    SendWindowUpdate(streamID, FLAG_ACK, INITIAL_WINDOW);
                    try { _acceptQueue.Add(s); } catch {}
                }
            }
        }
    }

    private void SendHeader(byte msgType, ushort flags, uint streamID, uint length) {
        byte[] h = new byte[HEADER_SIZE];
        h[0] = PROTO_VERSION; h[1] = msgType;
        h[2] = (byte)((flags >> 8) & 0xFF); h[3] = (byte)(flags & 0xFF);
        h[4] = (byte)((streamID >> 24) & 0xFF); h[5] = (byte)((streamID >> 16) & 0xFF);
        h[6] = (byte)((streamID >> 8) & 0xFF); h[7] = (byte)(streamID & 0xFF);
        h[8] = (byte)((length >> 24) & 0xFF); h[9] = (byte)((length >> 16) & 0xFF);
        h[10] = (byte)((length >> 8) & 0xFF); h[11] = (byte)(length & 0xFF);
        lock (_stream) { _stream.Write(h, 0, HEADER_SIZE); _stream.Flush(); }
    }

    public void SendData(uint streamID, byte[] payload) {
        lock (_stream) {
            SendHeader(TYPE_DATA, 0, streamID, (uint)payload.Length);
            _stream.Write(payload, 0, payload.Length);
            _stream.Flush();
        }
    }

    public void SendFin(uint streamID) { SendHeader(TYPE_DATA, FLAG_FIN, streamID, 0); }

    private void SendWindowUpdate(uint streamID, ushort flags, uint delta) {
        SendHeader(TYPE_WINDOW_UPDATE, flags, streamID, delta);
    }

    private void SendPingAck(uint pingID) { SendHeader(TYPE_PING, FLAG_ACK, 0, pingID); }

    private bool ReadExact(byte[] buffer, int count) {
        int total = 0;
        while (total < count) {
            int read = _stream.Read(buffer, total, count - total);
            if (read <= 0) return false;
            total += read;
        }
        return true;
    }
}

public static class LigoloFraming {
    public static byte ReadEnvelope(Stream s, out byte[] gobPayload) {
        byte[] header = new byte[5];
        if (!ReadExact(s, header, 5)) { gobPayload = null; return 0xFF; }
        byte msgType = header[0];
        int size = header[1] | (header[2] << 8) | (header[3] << 16) | (header[4] << 24);
        gobPayload = new byte[size];
        if (!ReadExact(s, gobPayload, size)) { gobPayload = null; return 0xFF; }
        return msgType;
    }

    public static void WriteEnvelope(Stream s, byte msgType, byte[] gobBytes) {
        byte[] header = new byte[5];
        int size = gobBytes.Length;
        header[0] = msgType;
        header[1] = (byte)(size & 0xFF); header[2] = (byte)((size >> 8) & 0xFF);
        header[3] = (byte)((size >> 16) & 0xFF); header[4] = (byte)((size >> 24) & 0xFF);
        lock (s) { s.Write(header, 0, 5); s.Write(gobBytes, 0, gobBytes.Length); s.Flush(); }
    }

    private static bool ReadExact(Stream s, byte[] buffer, int count) {
        int total = 0;
        while (total < count) {
            int read = s.Read(buffer, total, count - total);
            if (read <= 0) return false;
            total += read;
        }
        return true;
    }
}

}
'@

Add-Type -TypeDefinition $CSharpCode -Language CSharp

$MSG_INFO_REQUEST        = 0
$MSG_INFO_REPLY          = 1
$MSG_CONNECT_REQUEST     = 2
$MSG_CONNECT_RESPONSE    = 3
$MSG_HOSTPING_REQUEST    = 4
$MSG_HOSTPING_RESPONSE   = 5
$MSG_REDIRECTOR_REQUEST  = 6
$MSG_REDIRECTOR_RESPONSE = 7
$MSG_REDIR_CLOSE_REQ     = 10
$MSG_REDIR_CLOSE_RESP    = 11
$MSG_DISCONNECT_REQUEST  = 12
$MSG_DISCONNECT_RESPONSE = 13

$script:Redirectors = @{}

function New-AgentCertificate {
    param(
        [string]$CertFile,
        [string]$KeyFile,
        [string]$PfxFile,
        [string]$PfxPassword = ""
    )

    if ($PfxFile) {
        if (-not [System.IO.Path]::IsPathRooted($PfxFile)) {
            $PfxFile = Join-Path $PWD.Path $PfxFile
        }
        if (-not (Test-Path -LiteralPath $PfxFile)) {
            Write-Host "[-] PFX file not found: $PfxFile" -ForegroundColor Red
            throw "PFX file not found"
        }
        Write-Host "[*] Loading PFX: $PfxFile" -ForegroundColor Cyan
        if ($PfxPassword) {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxFile, $PfxPassword)
        } else {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxFile, "")
        }
    }

    if ($CertFile -and $KeyFile) {
        $certPem = Get-Content $CertFile -Raw
        $keyPem = Get-Content $KeyFile -Raw
        try {
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($certPem, $keyPem)
        } catch {
            Write-Host "[-] PEM loading failed (requires PowerShell 7+). Use -PfxFile instead." -ForegroundColor Red
            throw
        }
    }

    Write-Host "[-] No certificate provided. Use -CertFile/-KeyFile or -PfxFile." -ForegroundColor Red
    throw "No certificate provided"
}

function Get-AgentInfo {
    $hostname = [System.Environment]::MachineName
    $username = [System.Environment]::UserName
    $ifaces = [System.Collections.Generic.List[LigoloProto.NetInterfaceData]]::new()

    try {
        $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $netAdapters) {
            $iface = [LigoloProto.NetInterfaceData]::new()
            $iface.Index = $adapter.ifIndex
            $iface.MTU = $adapter.MtuSize
            $iface.Name = $adapter.Name
            $iface.HardwareAddr = $adapter.MacAddress
            $iface.Flags = 1
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
            foreach ($ip in $ipConfig) {
                if ($ip.AddressState -eq "Preferred") {
                    $iface.Addresses.Add("$($ip.IPAddress)/$($ip.PrefixLength)")
                }
            }
            $ifaces.Add($iface)
        }
    } catch {
        $iface = [LigoloProto.NetInterfaceData]::new()
        $iface.Name = "unknown"
        $iface.Addresses.Add("0.0.0.0/0")
        $ifaces.Add($iface)
    }

    return @{
        Name = "${username}@${hostname}"
        Hostname = $hostname
        Interfaces = $ifaces
        Redirectors = [System.Collections.Generic.List[LigoloProto.RedirectorData]]::new()
    }
}

function Test-HostAlive {
    param([string]$Address)
    try {
        return [bool](Test-Connection -ComputerName $Address -Count 1 -Quiet -ErrorAction SilentlyContinue)
    } catch { return $false }
}

function Start-TcpRelay {
    param([LigoloProto.YamuxStream]$Source, [System.Net.Sockets.NetworkStream]$Target)

    $buffer = New-Object byte[] 32768
    $connected = $true

    while ($connected) {
        $readTask = $Target.ReadAsync($buffer, 0, $buffer.Length)
        $sourceTask = [System.Threading.Tasks.Task]::Run({
            param($s, $b)
            return $s.Read($b, 0, $b.Length)
        }, @($Source, $buffer))

        $idx = [System.Threading.Tasks.Task]::WaitAny(@($readTask, $sourceTask))

        if ($idx -eq 0) {
            $n = $readTask.Result
            if ($n -le 0) { $connected = $false; break }
            $Source.Write($buffer, 0, $n)
        } else {
            $n = $sourceTask.Result
            if ($n -le 0) { $connected = $false; break }
            $Target.Write($buffer, 0, $n)
            $Target.Flush()
        }
    }

    $Target.Close()
    $Source.CloseStream()
}

function Invoke-StreamHandler {
    param([LigoloProto.YamuxStream]$Stream)

    try {
        $gobPayload = $null
        $msgType = [LigoloProto.LigoloFraming]::ReadEnvelope($Stream, [ref]$gobPayload)
        if ($msgType -eq 0xFF) { return }

        switch ($msgType) {
            $MSG_INFO_REQUEST {
                Write-Host "[*] InfoRequest" -ForegroundColor Cyan
                $info = Get-AgentInfo
                $valBytes = [LigoloProto.GobEncoder]::EncodeInfoReply(
                    $info.Name, $info.Hostname, $info.Interfaces, $info.Redirectors)
                $gobBytes = [LigoloProto.Gob]::BuildGobStream([LigoloProto.TypeDefs]::InfoReply, $valBytes)
                [LigoloProto.LigoloFraming]::WriteEnvelope($Stream, [byte]$MSG_INFO_REPLY, $gobBytes)
            }
            $MSG_CONNECT_REQUEST {
                $net=[byte]0; $transport=[byte]0; $address=""; $port=[System.UInt16]0
                $valMsg = [LigoloProto.GobDecoder]::ExtractValueMessage($gobPayload)
                if ($valMsg) {
                    [LigoloProto.GobDecoder]::DecodeConnectRequest($valMsg,
                        [ref]$net, [ref]$transport, [ref]$address, [ref]$port)
                }
                Write-Host "[*] ConnectRequest: ${address}:${port}" -ForegroundColor Cyan

                $established = $false
                $target = $null
                try {
                    $target = [System.Net.Sockets.TcpClient]::new()
                    $target.Connect($address, $port)
                    $established = $true
                } catch { $established = $false }

                $valBytes = [LigoloProto.GobEncoder]::EncodeConnectResponse($established, $false)
                $gobBytes = [LigoloProto.Gob]::BuildGobStream([LigoloProto.TypeDefs]::ConnectResponse, $valBytes)
                [LigoloProto.LigoloFraming]::WriteEnvelope($Stream, [byte]$MSG_CONNECT_RESPONSE, $gobBytes)

                if ($established) {
                    Write-Host "[+] Relay started: ${address}:${port}" -ForegroundColor Green
                    Start-TcpRelay -Source $Stream -Target $target.GetStream()
                    Write-Host "[-] Relay ended: ${address}:${port}" -ForegroundColor DarkGray
                } else {
                    Write-Host "[-] Connection failed: ${address}:${port}" -ForegroundColor Red
                }
            }
            $MSG_HOSTPING_REQUEST {
                $valMsg = [LigoloProto.GobDecoder]::ExtractValueMessage($gobPayload)
                $address = if ($valMsg) { [LigoloProto.GobDecoder]::DecodeHostPingRequest($valMsg) } else { "" }
                Write-Host "[*] HostPingRequest: $address" -ForegroundColor Cyan
                $alive = Test-HostAlive -Address $address
                $valBytes = [LigoloProto.GobEncoder]::EncodeHostPingResponse($alive)
                $gobBytes = [LigoloProto.Gob]::BuildGobStream([LigoloProto.TypeDefs]::HostPingResponse, $valBytes)
                [LigoloProto.LigoloFraming]::WriteEnvelope($Stream, [byte]$MSG_HOSTPING_RESPONSE, $gobBytes)
            }
            $MSG_REDIRECTOR_REQUEST {
                $valMsg = [LigoloProto.GobDecoder]::ExtractValueMessage($gobPayload)
                $id=""; $network=""; $from=""; $to=""
                if ($valMsg) {
                    [LigoloProto.GobDecoder]::DecodeRedirectorRequest($valMsg, [ref]$id, [ref]$network, [ref]$from, [ref]$to)
                }
                Write-Host "[*] RedirectorRequest: $from -> $to" -ForegroundColor Cyan
                $script:Redirectors[$id] = @{ From=$from; To=$to }
                $valBytes = [LigoloProto.GobEncoder]::EncodeRedirectorResponse($id, $false, "")
                $gobBytes = [LigoloProto.Gob]::BuildGobStream([LigoloProto.TypeDefs]::RedirectorResponse, $valBytes)
                [LigoloProto.LigoloFraming]::WriteEnvelope($Stream, [byte]$MSG_REDIRECTOR_RESPONSE, $gobBytes)
            }
            $MSG_REDIR_CLOSE_REQ {
                $valMsg = [LigoloProto.GobDecoder]::ExtractValueMessage($gobPayload)
                $id = if ($valMsg) { [LigoloProto.GobDecoder]::DecodeRedirectorCloseRequest($valMsg) } else { "" }
                Write-Host "[*] RedirectorCloseRequest: $id" -ForegroundColor Cyan
                if ($script:Redirectors.ContainsKey($id)) { $script:Redirectors.Remove($id) }
                $valBytes = [LigoloProto.GobEncoder]::EncodeRedirectorCloseResponse("", $false)
                $gobBytes = [LigoloProto.Gob]::BuildGobStream([LigoloProto.TypeDefs]::RedirectorCloseResponse, $valBytes)
                [LigoloProto.LigoloFraming]::WriteEnvelope($Stream, [byte]$MSG_REDIR_CLOSE_RESP, $gobBytes)
            }
            $MSG_DISCONNECT_REQUEST {
                Write-Host "[*] DisconnectRequest" -ForegroundColor Yellow
                $valBytes = [LigoloProto.GobEncoder]::EncodeDisconnectResponse()
                $gobBytes = [LigoloProto.Gob]::BuildGobStream([LigoloProto.TypeDefs]::DisconnectResponse, $valBytes)
                [LigoloProto.LigoloFraming]::WriteEnvelope($Stream, [byte]$MSG_DISCONNECT_RESPONSE, $gobBytes)
                $Stream.CloseStream()
                Write-Host "[*] Disconnected by server" -ForegroundColor Yellow
                exit 0
            }
            default { Write-Host "[?] Unknown msg type: $msgType" -ForegroundColor Red }
        }
    } catch {
        Write-Host "[-] Stream error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Start-HandleConnection {
    param([System.Net.Security.SslStream]$SslStream)
    $yamux = [LigoloProto.YamuxServer]::new($SslStream)
    while ($yamux.IsRunning) {
        try {
            $stream = $yamux.AcceptStream()
            if ($stream -eq $null) { break }
            Invoke-StreamHandler -Stream $stream
        } catch { break }
    }
    Write-Host "[-] Disconnected from server" -ForegroundColor Yellow
    exit 0
}

Write-Host "[*] Loading certificates..." -ForegroundColor Cyan
$agentCert = New-AgentCertificate -CertFile $CertFile -KeyFile $KeyFile -PfxFile $PfxFile -PfxPassword $PfxPassword

if (-not [System.IO.Path]::IsPathRooted($CACertFile)) {
    $CACertFile = Join-Path $PWD.Path $CACertFile
}
if (-not (Test-Path -LiteralPath $CACertFile)) {
    Write-Host "[-] CA cert file not found: $CACertFile" -ForegroundColor Red
    exit 1
}

if ($Server) {
    $serverParts = $Server -split ':'
    if ($serverParts.Count -lt 2) {
        Write-Host "[-] Invalid server address. Use: 10.0.0.5:11601" -ForegroundColor Red
        exit 1
    }
    $serverHost = $serverParts[0]
    $serverPort = [int]$serverParts[-1]

    Write-Host "[*] Dial-out mode: connecting to $Server" -ForegroundColor Green

    while ($true) {
        try {
            Write-Host "[*] Connecting to $Server ..." -ForegroundColor Cyan

            $tcpClient = [System.Net.Sockets.TcpClient]::new()
            $tcpClient.Connect($serverHost, $serverPort)
            Write-Host "[+] TCP connected" -ForegroundColor Green

            $remoteCertCallback = {
                param($sender, $cert, $chain, $sslErrors)
                return $true
            }
            $sslStream = [System.Net.Security.SslStream]::new(
                $tcpClient.GetStream(), $false, $remoteCertCallback, $null
            )

            $certColl = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new($agentCert)

            try {
                $sslProtos = [System.Security.Authentication.SslProtocols]::Tls13
                $sslStream.AuthenticateAsClient($serverHost, $certColl, $sslProtos, $false)
            } catch {
                $innerMsg = ""
                if ($_.Exception.InnerException) {
                    $innerMsg = " Inner: $($_.Exception.InnerException.Message)"
                }
                Write-Host "[-] TLS handshake failed: $($_.Exception.Message)$innerMsg" -ForegroundColor Red
                $sslStream.Close(); $tcpClient.Close()
                Start-Sleep -Seconds 5; continue
            }

            Write-Host "[+] Connected to server (TLS 1.3)" -ForegroundColor Green
            Start-HandleConnection -SslStream $sslStream

            $sslStream.Close()
            $tcpClient.Close()
        } catch {
            Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
        }

        Write-Host "[*] Reconnecting in 5s..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
    }

} else {
    $bindParts = $Bind -split ':'
    if ($bindParts.Count -lt 2) {
        Write-Host "[-] Invalid bind address. Use: 0.0.0.0:4444" -ForegroundColor Red
        exit 1
    }
    $bindPort = [int]$bindParts[-1]

    Write-Host "[*] Bind mode: listening on 0.0.0.0:$bindPort" -ForegroundColor Green

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $bindPort)
    $listener.Start()

    Write-Host "[*] Waiting for server connection..." -ForegroundColor Green

    while ($true) {
        try {
            $tcpClient = $listener.AcceptTcpClient()
            $remote = $tcpClient.Client.RemoteEndPoint.ToString()
            Write-Host "[+] Server connected from $remote" -ForegroundColor Green

            $serverCertCallback = {
                param($sender, $cert, $chain, $sslErrors)
                return $true
            }
            $sslStream = [System.Net.Security.SslStream]::new(
                $tcpClient.GetStream(), $false, $serverCertCallback, $null
            )

            try {
                $sslStream.AuthenticateAsServer($agentCert, $true,
                    [System.Security.Authentication.SslProtocols]::Tls13, $false)
            } catch {
                $innerMsg = ""
                if ($_.Exception.InnerException) {
                    $innerMsg = " Inner: $($_.Exception.InnerException.Message)"
                }
                Write-Host "[-] TLS failed: $($_.Exception.Message)$innerMsg" -ForegroundColor Red
                $sslStream.Close(); $tcpClient.Close(); continue
            }

            Start-HandleConnection -SslStream $sslStream
            $sslStream.Close()
            $tcpClient.Close()
        } catch {
            Write-Host "[-] $($_.Exception.Message)" -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}
