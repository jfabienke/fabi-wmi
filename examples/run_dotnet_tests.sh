#!/usr/bin/env bash
# Run the .NET E2E tests for linux-wmi against a Windows host, or with --stub
# against the library's canned stub backend (no host needed).
# Usage: ./run_dotnet_tests.sh [OPTIONS]
# Options:
#   --host HOST         Windows host to test against (default: from config)
#   --user USER         Username for authentication
#   --pass PASS         Password for authentication
#   --domain DOMAIN     Domain for authentication
#   --stub              Build with test-support and run against the stub backend
#   --filter FILTER     xUnit test filter expression
#   --verbose           Enable verbose output
#   --skip-build        Skip building the Rust library
#   --help              Show this help message

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_DIR="${REPO_ROOT}/tests/e2e-dotnet"
LIB_DIR="${REPO_ROOT}/target/debug"

# Parse command line arguments
HOST=""
USERNAME_ARG=""
PASS=""
DOMAIN=""
FILTER=""
VERBOSE=false
SKIP_BUILD=false
STUB=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --user)
            USERNAME_ARG="$2"
            shift 2
            ;;
        --pass)
            PASS="$2"
            shift 2
            ;;
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --filter)
            FILTER="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --stub)
            STUB=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --help)
            grep '^#' "$0" | grep -v '#!/' | sed 's/^# //'
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Build the Rust library if not skipped
if [[ "${SKIP_BUILD}" == "false" ]]; then
    echo "🔨 Building fabi-wmi library..."
    cd "${REPO_ROOT}"
    if [[ "${STUB}" == "true" ]]; then
        cargo build --lib --features test-support
    else
        cargo build --lib
    fi

    # Check if the library was built
    if [[ ! -f "${LIB_DIR}/libfabi_wmi.dylib" ]] && [[ ! -f "${LIB_DIR}/libfabi_wmi.so" ]]; then
        echo "❌ Failed to build fabi-wmi library" >&2
        exit 1
    fi

    # Copy library to test output directory for .NET to find it
    if [[ -f "${LIB_DIR}/libfabi_wmi.dylib" ]]; then
        LIB_FILE="${LIB_DIR}/libfabi_wmi.dylib"
    else
        LIB_FILE="${LIB_DIR}/libfabi_wmi.so"
    fi
fi

# Set environment variables for test configuration
if [[ -n "${HOST}" ]]; then
    export WMI_TEST_DEFAULTHOST="${HOST}"
fi
if [[ -n "${USERNAME_ARG}" ]]; then
    export WMI_TEST_DEFAULTUSERNAME="${USERNAME_ARG}"
fi
if [[ "${STUB}" == "true" ]]; then
    export LINUX_WMI_USE_STUB=1
fi
if [[ -n "${PASS}" ]]; then
    export WMI_TEST_DEFAULTPASSWORD="${PASS}"
fi
if [[ -n "${DOMAIN}" ]]; then
    export WMI_TEST_DEFAULTDOMAIN="${DOMAIN}"
fi

# Build filter expression
FILTER_ARG=""
if [[ -n "${FILTER}" ]]; then
    FILTER_ARG="--filter ${FILTER}"
fi

# Set verbosity
VERBOSITY="minimal"
if [[ "${VERBOSE}" == "true" ]]; then
    VERBOSITY="detailed"
fi

# Print test configuration
cat <<INFO
🚀 Running .NET E2E tests for linux-wmi
   Test directory: ${TEST_DIR}
   Library: ${LIB_FILE:-"Using existing build"}
   Host: ${HOST:-"<from config>"}
   User: ${USERNAME_ARG:-"<from config>"}
   Stub backend: ${STUB}
   Domain: ${DOMAIN:-"<from config>"}
   Filter: ${FILTER:-"<none>"}
   Verbosity: ${VERBOSITY}
INFO

# Change to test directory
cd "${TEST_DIR}"

# Restore NuGet packages if needed
if [[ ! -d "bin" ]] || [[ ! -d "obj" ]]; then
    echo "📦 Restoring NuGet packages..."
    dotnet restore
fi

# Build the test project
echo "🔨 Building test project..."
dotnet build --configuration Debug --no-restore

# Copy the Rust library to the test output directory
if [[ -n "${LIB_FILE:-}" ]]; then
    TEST_OUTPUT="${TEST_DIR}/bin/Debug/net10.0"
    echo "📄 Copying library to test output: ${TEST_OUTPUT}"
    cp "${LIB_FILE}" "${TEST_OUTPUT}/"

    # On macOS, we might need to handle the .dylib extension
    if [[ "${LIB_FILE}" == *.dylib ]]; then
        # .NET might look for .so, so create a symlink
        (cd "${TEST_OUTPUT}" && ln -sf "$(basename "${LIB_FILE}")" "libfabi_wmi.so" 2>/dev/null || true)
    fi
fi

# Run the tests
echo "🧪 Running tests..."
if dotnet test \
    --no-build \
    --configuration Debug \
    --verbosity "${VERBOSITY}" \
    --logger "console;verbosity=${VERBOSITY}" \
    ${FILTER_ARG} ; then
    echo "✅ All tests passed!"
    exit 0
else
    echo "❌ Some tests failed. Check the output above for details." >&2
    exit 1
fi