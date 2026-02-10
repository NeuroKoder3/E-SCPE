using System;
using System.Runtime.InteropServices;

namespace EscpeWinUI.Services;

public sealed class EscpeNative
{
    private const string DllName = "escpe_core.dll";

    public string InitLedger(string dbPath, string? dbKey)
    {
        var status = escpe_init_ledger(dbPath, dbKey, out var ptr);
        return HandleResult(status, ptr);
    }

    public string Scan(
        string dbPath,
        string? dbKey,
        string serial,
        double chshThreshold,
        string signingKeyPem,
        string? signingCertPem)
    {
        var status = escpe_scan(
            dbPath,
            dbKey,
            serial,
            chshThreshold,
            signingKeyPem,
            signingCertPem,
            out var ptr);
        return HandleResult(status, ptr);
    }

    public string VerifyLedger(string dbPath, string? dbKey)
    {
        var status = escpe_verify_ledger(dbPath, dbKey, out var ptr);
        return HandleResult(status, ptr);
    }

    public string Audit(
        string dbPath,
        string? dbKey,
        string csvPath,
        string outDir,
        double chshThreshold,
        string signingKeyPem,
        string? signingCertPem)
    {
        var status = escpe_audit(
            dbPath,
            dbKey,
            csvPath,
            outDir,
            chshThreshold,
            signingKeyPem,
            signingCertPem,
            out var ptr);
        return HandleResult(status, ptr);
    }

    public string Keygen(string outDir, string? commonName)
    {
        var status = escpe_keygen(outDir, commonName, out var ptr);
        return HandleResult(status, ptr);
    }

    public string MachineFingerprint()
    {
        var status = escpe_machine_fingerprint(out var ptr);
        return HandleResult(status, ptr);
    }

    public string CheckLicense(string licensePath, string vendorPubkeyB64)
    {
        var status = escpe_check_license(licensePath, vendorPubkeyB64, out var ptr);
        return HandleResult(status, ptr);
    }

    public string Version()
    {
        var status = escpe_version(out var ptr);
        return HandleResult(status, ptr);
    }

    public string ExportLedger(string dbPath, string? dbKey, string exportPath)
    {
        var status = escpe_export_ledger(dbPath, dbKey, exportPath, out var ptr);
        return HandleResult(status, ptr);
    }

    public string ImportLedger(string jsonPath, string dbPath, string? dbKey)
    {
        var status = escpe_import_ledger(jsonPath, dbPath, dbKey, out var ptr);
        return HandleResult(status, ptr);
    }

    private static string HandleResult(int status, IntPtr jsonPtr)
    {
        if (status == 0)
        {
            return ReadAndFree(jsonPtr);
        }

        if (jsonPtr != IntPtr.Zero)
        {
            escpe_free_string(jsonPtr);
        }

        throw new EscpeNativeException(status, GetLastError());
    }

    private static string ReadAndFree(IntPtr jsonPtr)
    {
        try
        {
            return jsonPtr == IntPtr.Zero
                ? string.Empty
                : Marshal.PtrToStringUTF8(jsonPtr) ?? string.Empty;
        }
        finally
        {
            if (jsonPtr != IntPtr.Zero)
            {
                escpe_free_string(jsonPtr);
            }
        }
    }

    private static string GetLastError()
    {
        var required = escpe_last_error(IntPtr.Zero, 0);
        if (required <= 0)
        {
            return "unknown error";
        }

        var buf = Marshal.AllocHGlobal(required);
        try
        {
            escpe_last_error(buf, required);
            return Marshal.PtrToStringUTF8(buf) ?? "unknown error";
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_last_error(IntPtr buf, int buf_len);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void escpe_free_string(IntPtr ptr);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_version(out IntPtr out_json);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_init_ledger(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string db_path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? db_key,
        out IntPtr out_json);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_scan(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string db_path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? db_key,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string serial,
        double chsh_threshold,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string signing_key_pem,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? signing_cert_pem,
        out IntPtr out_json);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_verify_ledger(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string db_path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? db_key,
        out IntPtr out_json);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_audit(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string db_path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? db_key,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string csv_path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string out_dir,
        double chsh_threshold,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string signing_key_pem,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? signing_cert_pem,
        out IntPtr out_json);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_keygen(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string out_dir,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? common_name,
        out IntPtr out_json);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_machine_fingerprint(out IntPtr out_json);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_check_license(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string license_path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string vendor_pubkey_b64,
        out IntPtr out_json);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_export_ledger(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string db_path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? db_key,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string export_path,
        out IntPtr out_json);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern int escpe_import_ledger(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string json_path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string db_path,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string? db_key,
        out IntPtr out_json);
}

public sealed class EscpeNativeException : Exception
{
    public int StatusCode { get; }

    public EscpeNativeException(int statusCode, string message)
        : base(message)
    {
        StatusCode = statusCode;
    }
}
