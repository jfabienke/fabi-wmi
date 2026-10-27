namespace LinuxWmi.E2ETests.Infrastructure
{
    /// <summary>
    /// Values of WmiException.Code: the server's HRESULT when it sent one,
    /// otherwise -1 (network errors, timeouts, invalid input).
    /// </summary>
    public static class WmiStatus
    {
        public const int NoHresult = -1;
        public const int AccessDenied = unchecked((int)0x80070005);         // E_ACCESSDENIED
        public const int NotFound = unchecked((int)0x80041002);             // WBEM_E_NOT_FOUND
        public const int InvalidNamespace = unchecked((int)0x8004100E);     // WBEM_E_INVALID_NAMESPACE
        public const int InvalidClass = unchecked((int)0x80041010);         // WBEM_E_INVALID_CLASS
        public const int InvalidQuery = unchecked((int)0x80041017);         // WBEM_E_INVALID_QUERY
        public const int MethodNotImplemented = unchecked((int)0x80041055); // WBEM_E_METHOD_NOT_IMPLEMENTED
    }
}
