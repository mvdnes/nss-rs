pub type NSSResult<T> = Result<T, NSSError>;

#[repr(i32)]
#[deriving(Show, FromPrimitive)]
#[allow(non_camel_case_types)]
pub enum NSSError
{
    /// Unkown / No error
    UNKNOWN = 0,

    /// Memory allocation attempt failed
    PR_OUT_OF_MEMORY_ERROR = -6000,

    /// Invalid file descriptor
    PR_BAD_DESCRIPTOR_ERROR = -5999,

    /// The operation would have blocked
    PR_WOULD_BLOCK_ERROR = -5998,

    /// Invalid memory address argument
    PR_ACCESS_FAULT_ERROR = -5997,

    /// Invalid function for file type
    PR_INVALID_METHOD_ERROR = -5996,

    /// Invalid memory address argument
    PR_ILLEGAL_ACCESS_ERROR = -5995,

    /// Some unknown error has occurred
    PR_UNKNOWN_ERROR = -5994,

    /// Operation interrupted by another thread
    PR_PENDING_INTERRUPT_ERROR = -5993,

    /// function not implemented
    PR_NOT_IMPLEMENTED_ERROR = -5992,

    /// I/O function error
    PR_IO_ERROR = -5991,

    /// I/O operation timed out
    PR_IO_TIMEOUT_ERROR = -5990,

    /// I/O operation on busy file descriptor
    PR_IO_PENDING_ERROR = -5989,

    /// The directory could not be opened
    PR_DIRECTORY_OPEN_ERROR = -5988,

    /// Invalid function argument
    PR_INVALID_ARGUMENT_ERROR = -5987,

    /// Network address not available (in use?)
    PR_ADDRESS_NOT_AVAILABLE_ERROR = -5986,

    /// Network address type not supported
    PR_ADDRESS_NOT_SUPPORTED_ERROR = -5985,

    /// Already connected
    PR_IS_CONNECTED_ERROR = -5984,

    /// Network address is invalid
    PR_BAD_ADDRESS_ERROR = -5983,

    /// Local Network address is in use
    PR_ADDRESS_IN_USE_ERROR = -5982,

    /// Connection refused by peer
    PR_CONNECT_REFUSED_ERROR = -5981,

    /// Network address is presently unreachable
    PR_NETWORK_UNREACHABLE_ERROR = -5980,

    /// Connection attempt timed out
    PR_CONNECT_TIMEOUT_ERROR = -5979,

    /// Network file descriptor is not connected
    PR_NOT_CONNECTED_ERROR = -5978,

    /// Failure to load dynamic library
    PR_LOAD_LIBRARY_ERROR = -5977,

    /// Failure to unload dynamic library
    PR_UNLOAD_LIBRARY_ERROR = -5976,

    /// Symbol not found in any of the loaded dynamic libraries
    PR_FIND_SYMBOL_ERROR = -5975,

    /// Insufficient system resources
    PR_INSUFFICIENT_RESOURCES_ERROR = -5974,

    /// A directory lookup on a network address has failed
    PR_DIRECTORY_LOOKUP_ERROR = -5973,

    /// Attempt to access a TPD key that is out of range
    PR_TPD_RANGE_ERROR = -5972,

    /// Process open FD table is full
    PR_PROC_DESC_TABLE_FULL_ERROR = -5971,

    /// System open FD table is full
    PR_SYS_DESC_TABLE_FULL_ERROR = -5970,

    /// Network operation attempted on non-network file descriptor
    PR_NOT_SOCKET_ERROR = -5969,

    /// TCP-specific function attempted on a non-TCP file descriptor
    PR_NOT_TCP_SOCKET_ERROR = -5968,

    /// TCP file descriptor is already bound
    PR_SOCKET_ADDRESS_IS_BOUND_ERROR = -5967,

    /// Access Denied
    PR_NO_ACCESS_RIGHTS_ERROR = -5966,

    /// The requested operation is not supported by the platform
    PR_OPERATION_NOT_SUPPORTED_ERROR = -5965,

    /// The host operating system does not support the protocol requested
    PR_PROTOCOL_NOT_SUPPORTED_ERROR = -5964,

    /// Access to the remote file has been severed
    PR_REMOTE_FILE_ERROR = -5963,

    /// The value requested is too large to be stored in the data buffer provided
    PR_BUFFER_OVERFLOW_ERROR = -5962,

    /// TCP connection reset by peer
    PR_CONNECT_RESET_ERROR = -5961,

    /// Unused
    PR_RANGE_ERROR = -5960,

    /// The operation would have deadlocked
    PR_DEADLOCK_ERROR = -5959,

    /// The file is already locked
    PR_FILE_IS_LOCKED_ERROR = -5958,

    /// Write would result in file larger than the system allows
    PR_FILE_TOO_BIG_ERROR = -5957,

    /// The device for storing the file is full
    PR_NO_DEVICE_SPACE_ERROR = -5956,

    /// Unused
    PR_PIPE_ERROR = -5955,

    /// Unused
    PR_NO_SEEK_DEVICE_ERROR = -5954,

    /// Cannot perform a normal file operation on a directory
    PR_IS_DIRECTORY_ERROR = -5953,

    /// Symbolic link loop
    PR_LOOP_ERROR = -5952,

    /// File name is too long
    PR_NAME_TOO_LONG_ERROR = -5951,

    /// File not found
    PR_FILE_NOT_FOUND_ERROR = -5950,

    /// Cannot perform directory operation on a normal file
    PR_NOT_DIRECTORY_ERROR = -5949,

    /// Cannot write to a read-only file system
    PR_READ_ONLY_FILESYSTEM_ERROR = -5948,

    /// Cannot delete a directory that is not empty
    PR_DIRECTORY_NOT_EMPTY_ERROR = -5947,

    /// Cannot delete or rename a file object while the file system is busy
    PR_FILESYSTEM_MOUNTED_ERROR = -5946,

    /// Cannot rename a file to a file system on another device
    PR_NOT_SAME_DEVICE_ERROR = -5945,

    /// The directory object in the file system is corrupted
    PR_DIRECTORY_CORRUPTED_ERROR = -5944,

    /// Cannot create or rename a filename that already exists
    PR_FILE_EXISTS_ERROR = -5943,

    /// Directory is full.  No additional filenames may be added
    PR_MAX_DIRECTORY_ENTRIES_ERROR = -5942,

    /// The required device was in an invalid state
    PR_INVALID_DEVICE_STATE_ERROR = -5941,

    /// The device is locked
    PR_DEVICE_IS_LOCKED_ERROR = -5940,

    /// No more entries in the directory
    PR_NO_MORE_FILES_ERROR = -5939,

    /// Encountered end of file
    PR_END_OF_FILE_ERROR = -5938,

    /// Seek error
    PR_FILE_SEEK_ERROR = -5937,

    /// The file is busy
    PR_FILE_IS_BUSY_ERROR = -5936,

    /// The I/O operation was aborted
    PR_OPERATION_ABORTED_ERROR = -5935,

    /// Operation is still in progress (probably a non-blocking connect)
    PR_IN_PROGRESS_ERROR = -5934,

    /// Operation has already been initiated (probably a non-blocking connect)
    PR_ALREADY_INITIATED_ERROR = -5933,

    /// The wait group is empty
    PR_GROUP_EMPTY_ERROR = -5932,

    /// Object state improper for request
    PR_INVALID_STATE_ERROR = -5931,

    /// Network is down
    PR_NETWORK_DOWN_ERROR = -5930,

    /// Socket shutdown
    PR_SOCKET_SHUTDOWN_ERROR = -5929,

    /// Connection aborted
    PR_CONNECT_ABORTED_ERROR = -5928,

    /// Host is unreachable
    PR_HOST_UNREACHABLE_ERROR = -5927,

    /// The library is not loaded
    PR_LIBRARY_NOT_LOADED_ERROR = -5926,

    /// The one-time function was previously called and failed. Its error code is no longer available
    PR_CALL_ONCE_ERROR = -5925,

    /// Placeholder for the end of the list
    PR_MAX_ERROR = -5924,

    SEC_ERROR_IO = -0x2000 + 0,
    SEC_ERROR_LIBRARY_FAILURE = -0x2000 + 1,
    SEC_ERROR_BAD_DATA = -0x2000 + 2,
    SEC_ERROR_OUTPUT_LEN = -0x2000 + 3,
    SEC_ERROR_INPUT_LEN = -0x2000 + 4,
    SEC_ERROR_INVALID_ARGS = -0x2000 + 5,
    SEC_ERROR_INVALID_ALGORITHM = -0x2000 + 6,
    SEC_ERROR_INVALID_AVA = -0x2000 + 7,
    SEC_ERROR_INVALID_TIME = -0x2000 + 8,
    SEC_ERROR_BAD_DER = -0x2000 + 9,
    SEC_ERROR_BAD_SIGNATURE = -0x2000 + 10,
    SEC_ERROR_EXPIRED_CERTIFICATE = -0x2000 + 11,
    SEC_ERROR_REVOKED_CERTIFICATE = -0x2000 + 12,
    SEC_ERROR_UNKNOWN_ISSUER = -0x2000 + 13,
    SEC_ERROR_BAD_KEY = -0x2000 + 14,
    SEC_ERROR_BAD_PASSWORD = -0x2000 + 15,
    SEC_ERROR_RETRY_PASSWORD = -0x2000 + 16,
    SEC_ERROR_NO_NODELOCK = -0x2000 + 17,
    SEC_ERROR_BAD_DATABASE = -0x2000 + 18,
    SEC_ERROR_NO_MEMORY = -0x2000 + 19,
    SEC_ERROR_UNTRUSTED_ISSUER = -0x2000 + 20,
    SEC_ERROR_UNTRUSTED_CERT = -0x2000 + 21,
    SEC_ERROR_DUPLICATE_CERT = (-0x2000 + 22),
    SEC_ERROR_DUPLICATE_CERT_NAME = (-0x2000 + 23),
    SEC_ERROR_ADDING_CERT = (-0x2000 + 24),
    SEC_ERROR_FILING_KEY = (-0x2000 + 25),
    SEC_ERROR_NO_KEY = (-0x2000 + 26),
    SEC_ERROR_CERT_VALID = (-0x2000 + 27),
    SEC_ERROR_CERT_NOT_VALID = (-0x2000 + 28),
    SEC_ERROR_CERT_NO_RESPONSE = (-0x2000 + 29),
    SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE = (-0x2000 + 30),
    SEC_ERROR_CRL_EXPIRED = (-0x2000 + 31),
    SEC_ERROR_CRL_BAD_SIGNATURE = (-0x2000 + 32),
    SEC_ERROR_CRL_INVALID = (-0x2000 + 33),
    SEC_ERROR_EXTENSION_VALUE_INVALID = (-0x2000 + 34),
    SEC_ERROR_EXTENSION_NOT_FOUND = (-0x2000 + 35),
    SEC_ERROR_CA_CERT_INVALID = (-0x2000 + 36),
    SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID = (-0x2000 + 37),
    SEC_ERROR_CERT_USAGES_INVALID = (-0x2000 + 38),
    SEC_INTERNAL_ONLY = (-0x2000 + 39),
    SEC_ERROR_INVALID_KEY = (-0x2000 + 40),
    SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION = (-0x2000 + 41),
    SEC_ERROR_OLD_CRL = (-0x2000 + 42),
    SEC_ERROR_NO_EMAIL_CERT = (-0x2000 + 43),
    SEC_ERROR_NO_RECIPIENT_CERTS_QUERY = (-0x2000 + 44),
    SEC_ERROR_NOT_A_RECIPIENT = (-0x2000 + 45),
    SEC_ERROR_PKCS7_KEYALG_MISMATCH = (-0x2000 + 46),
    SEC_ERROR_PKCS7_BAD_SIGNATURE = (-0x2000 + 47),
    SEC_ERROR_UNSUPPORTED_KEYALG = (-0x2000 + 48),
    SEC_ERROR_DECRYPTION_DISALLOWED = (-0x2000 + 49),
    XP_SEC_FORTEZZA_BAD_CARD = (-0x2000 + 50),
    XP_SEC_FORTEZZA_NO_CARD = (-0x2000 + 51),
    XP_SEC_FORTEZZA_NONE_SELECTED = (-0x2000 + 52),
    XP_SEC_FORTEZZA_MORE_INFO = (-0x2000 + 53),
    XP_SEC_FORTEZZA_PERSON_NOT_FOUND = (-0x2000 + 54),
    XP_SEC_FORTEZZA_NO_MORE_INFO = (-0x2000 + 55),
    XP_SEC_FORTEZZA_BAD_PIN = (-0x2000 + 56),
    XP_SEC_FORTEZZA_PERSON_ERROR = (-0x2000 + 57),
    SEC_ERROR_NO_KRL = (-0x2000 + 58),
    SEC_ERROR_KRL_EXPIRED = (-0x2000 + 59),
    SEC_ERROR_KRL_BAD_SIGNATURE = (-0x2000 + 60),
    SEC_ERROR_REVOKED_KEY = (-0x2000 + 61),
    SEC_ERROR_KRL_INVALID = (-0x2000 + 62),
    SEC_ERROR_NEED_RANDOM = (-0x2000 + 63),
    SEC_ERROR_NO_MODULE = (-0x2000 + 64),
    SEC_ERROR_NO_TOKEN = (-0x2000 + 65),
    SEC_ERROR_READ_ONLY = (-0x2000 + 66),
    SEC_ERROR_NO_SLOT_SELECTED = (-0x2000 + 67),
    SEC_ERROR_CERT_NICKNAME_COLLISION = (-0x2000 + 68),
    SEC_ERROR_KEY_NICKNAME_COLLISION = (-0x2000 + 69),
    SEC_ERROR_SAFE_NOT_CREATED = (-0x2000 + 70),
    SEC_ERROR_BAGGAGE_NOT_CREATED = (-0x2000 + 71),
    XP_JAVA_REMOVE_PRINCIPAL_ERROR = (-0x2000 + 72),
    XP_JAVA_DELETE_PRIVILEGE_ERROR = (-0x2000 + 73),
    XP_JAVA_CERT_NOT_EXISTS_ERROR = (-0x2000 + 74),
    SEC_ERROR_BAD_EXPORT_ALGORITHM = (-0x2000 + 75),
    SEC_ERROR_EXPORTING_CERTIFICATES = (-0x2000 + 76),
    SEC_ERROR_IMPORTING_CERTIFICATES = (-0x2000 + 77),
    SEC_ERROR_PKCS12_DECODING_PFX = (-0x2000 + 78),
    SEC_ERROR_PKCS12_INVALID_MAC = (-0x2000 + 79),
    SEC_ERROR_PKCS12_UNSUPPORTED_MAC_ALGORITHM = (-0x2000 + 80),
    SEC_ERROR_PKCS12_UNSUPPORTED_TRANSPORT_MODE = (-0x2000 + 81),
    SEC_ERROR_PKCS12_CORRUPT_PFX_STRUCTURE = (-0x2000 + 82),
    SEC_ERROR_PKCS12_UNSUPPORTED_PBE_ALGORITHM = (-0x2000 + 83),
    SEC_ERROR_PKCS12_UNSUPPORTED_VERSION = (-0x2000 + 84),
    SEC_ERROR_PKCS12_PRIVACY_PASSWORD_INCORRECT = (-0x2000 + 85),
    SEC_ERROR_PKCS12_CERT_COLLISION = (-0x2000 + 86),
    SEC_ERROR_USER_CANCELLED = (-0x2000 + 87),
    SEC_ERROR_PKCS12_DUPLICATE_DATA = (-0x2000 + 88),
    SEC_ERROR_MESSAGE_SEND_ABORTED = (-0x2000 + 89),
    SEC_ERROR_INADEQUATE_KEY_USAGE = (-0x2000 + 90),
    SEC_ERROR_INADEQUATE_CERT_TYPE = (-0x2000 + 91),
    SEC_ERROR_CERT_ADDR_MISMATCH = (-0x2000 + 92),
    SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY = (-0x2000 + 93),
    SEC_ERROR_PKCS12_IMPORTING_CERT_CHAIN = (-0x2000 + 94),
    SEC_ERROR_PKCS12_UNABLE_TO_LOCATE_OBJECT_BY_NAME = (-0x2000 + 95),
    SEC_ERROR_PKCS12_UNABLE_TO_EXPORT_KEY = (-0x2000 + 96),
    SEC_ERROR_PKCS12_UNABLE_TO_WRITE = (-0x2000 + 97),
    SEC_ERROR_PKCS12_UNABLE_TO_READ = (-0x2000 + 98),
    SEC_ERROR_PKCS12_KEY_DATABASE_NOT_INITIALIZED = (-0x2000 + 99),
    SEC_ERROR_KEYGEN_FAIL = (-0x2000 + 100),
    SEC_ERROR_INVALID_PASSWORD = (-0x2000 + 101),
    SEC_ERROR_RETRY_OLD_PASSWORD = (-0x2000 + 102),
    SEC_ERROR_BAD_NICKNAME = (-0x2000 + 103),
    SEC_ERROR_NOT_FORTEZZA_ISSUER = (-0x2000 + 104),
    SEC_ERROR_CANNOT_MOVE_SENSITIVE_KEY = (-0x2000 + 105),
    SEC_ERROR_JS_INVALID_MODULE_NAME = (-0x2000 + 106),
    SEC_ERROR_JS_INVALID_DLL = (-0x2000 + 107),
    SEC_ERROR_JS_ADD_MOD_FAILURE = (-0x2000 + 108),
    SEC_ERROR_JS_DEL_MOD_FAILURE = (-0x2000 + 109),
    SEC_ERROR_OLD_KRL = (-0x2000 + 110),
    SEC_ERROR_CKL_CONFLICT = (-0x2000 + 111),
    SEC_ERROR_CERT_NOT_IN_NAME_SPACE = (-0x2000 + 112),
    SEC_ERROR_KRL_NOT_YET_VALID = (-0x2000 + 113),
    SEC_ERROR_CRL_NOT_YET_VALID = (-0x2000 + 114),
    SEC_ERROR_UNKNOWN_CERT = (-0x2000 + 115),
    SEC_ERROR_UNKNOWN_SIGNER = (-0x2000 + 116),
    SEC_ERROR_CERT_BAD_ACCESS_LOCATION = (-0x2000 + 117),
    SEC_ERROR_OCSP_UNKNOWN_RESPONSE_TYPE = (-0x2000 + 118),
    SEC_ERROR_OCSP_BAD_HTTP_RESPONSE = (-0x2000 + 119),
    SEC_ERROR_OCSP_MALFORMED_REQUEST = (-0x2000 + 120),
    SEC_ERROR_OCSP_SERVER_ERROR = (-0x2000 + 121),
    SEC_ERROR_OCSP_TRY_SERVER_LATER = (-0x2000 + 122),
    SEC_ERROR_OCSP_REQUEST_NEEDS_SIG = (-0x2000 + 123),
    SEC_ERROR_OCSP_UNAUTHORIZED_REQUEST = (-0x2000 + 124),
    SEC_ERROR_OCSP_UNKNOWN_RESPONSE_STATUS = (-0x2000 + 125),
    SEC_ERROR_OCSP_UNKNOWN_CERT = (-0x2000 + 126),
    SEC_ERROR_OCSP_NOT_ENABLED = (-0x2000 + 127),
    SEC_ERROR_OCSP_NO_DEFAULT_RESPONDER = (-0x2000 + 128),
    SEC_ERROR_OCSP_MALFORMED_RESPONSE = (-0x2000 + 129),
    SEC_ERROR_OCSP_UNAUTHORIZED_RESPONSE = (-0x2000 + 130),
    SEC_ERROR_OCSP_FUTURE_RESPONSE = (-0x2000 + 131),
    SEC_ERROR_OCSP_OLD_RESPONSE = (-0x2000 + 132),
    SEC_ERROR_DIGEST_NOT_FOUND = (-0x2000 + 133),
    SEC_ERROR_UNSUPPORTED_MESSAGE_TYPE = (-0x2000 + 134),
    SEC_ERROR_MODULE_STUCK = (-0x2000 + 135),
    SEC_ERROR_BAD_TEMPLATE = (-0x2000 + 136),
    SEC_ERROR_CRL_NOT_FOUND = (-0x2000 + 137),
    SEC_ERROR_REUSED_ISSUER_AND_SERIAL = (-0x2000 + 138),
    SEC_ERROR_BUSY = (-0x2000 + 139),
    SEC_ERROR_EXTRA_INPUT = (-0x2000 + 140),
    SEC_ERROR_UNSUPPORTED_ELLIPTIC_CURVE = (-0x2000 + 141),
    SEC_ERROR_UNSUPPORTED_EC_POINT_FORM = (-0x2000 + 142),
    SEC_ERROR_UNRECOGNIZED_OID = (-0x2000 + 143),
    SEC_ERROR_OCSP_INVALID_SIGNING_CERT = (-0x2000 + 144),
    SEC_ERROR_REVOKED_CERTIFICATE_CRL = (-0x2000 + 145),
    SEC_ERROR_REVOKED_CERTIFICATE_OCSP = (-0x2000 + 146),
    SEC_ERROR_CRL_INVALID_VERSION = (-0x2000 + 147),
    SEC_ERROR_CRL_V1_CRITICAL_EXTENSION = (-0x2000 + 148),
    SEC_ERROR_CRL_UNKNOWN_CRITICAL_EXTENSION = (-0x2000 + 149),
    SEC_ERROR_UNKNOWN_OBJECT_TYPE = (-0x2000 + 150),
    SEC_ERROR_INCOMPATIBLE_PKCS11 = (-0x2000 + 151),
    SEC_ERROR_NO_EVENT = (-0x2000 + 152),
    SEC_ERROR_CRL_ALREADY_EXISTS = (-0x2000 + 153),
    SEC_ERROR_NOT_INITIALIZED = (-0x2000 + 154),
    SEC_ERROR_TOKEN_NOT_LOGGED_IN = (-0x2000 + 155),
    SEC_ERROR_OCSP_RESPONDER_CERT_INVALID = (-0x2000 + 156),
    SEC_ERROR_OCSP_BAD_SIGNATURE = (-0x2000 + 157),
    SEC_ERROR_OUT_OF_SEARCH_LIMITS = (-0x2000 + 158),
    SEC_ERROR_INVALID_POLICY_MAPPING = (-0x2000 + 159),
    SEC_ERROR_POLICY_VALIDATION_FAILED = (-0x2000 + 160),
    SEC_ERROR_UNKNOWN_AIA_LOCATION_TYPE = (-0x2000 + 161),
    SEC_ERROR_BAD_HTTP_RESPONSE = (-0x2000 + 162),
    SEC_ERROR_BAD_LDAP_RESPONSE = (-0x2000 + 163),
    SEC_ERROR_FAILED_TO_ENCODE_DATA = (-0x2000 + 164),
    SEC_ERROR_BAD_INFO_ACCESS_LOCATION = (-0x2000 + 165),
    SEC_ERROR_LIBPKIX_INTERNAL = (-0x2000 + 166),
    SEC_ERROR_PKCS11_GENERAL_ERROR = (-0x2000 + 167),
    SEC_ERROR_PKCS11_FUNCTION_FAILED = (-0x2000 + 168),
    SEC_ERROR_PKCS11_DEVICE_ERROR = (-0x2000 + 169),
    SEC_ERROR_BAD_INFO_ACCESS_METHOD = (-0x2000 + 170),
    SEC_ERROR_CRL_IMPORT_FAILED = (-0x2000 + 171),
    SEC_ERROR_EXPIRED_PASSWORD = (-0x2000 + 172),
    SEC_ERROR_LOCKED_PASSWORD = (-0x2000 + 173),
    SEC_ERROR_UNKNOWN_PKCS11_ERROR = (-0x2000 + 174),
    SEC_ERROR_BAD_CRL_DP_URL = (-0x2000 + 175),
    SEC_ERROR_CERT_SIGNATURE_ALGORITHM_DISABLED = (-0x2000 + 176),
    SEC_ERROR_LEGACY_DATABASE = (-0x2000 + 177),
    SEC_ERROR_APPLICATION_CALLBACK_ERROR = (-0x2000 + 178),
}
