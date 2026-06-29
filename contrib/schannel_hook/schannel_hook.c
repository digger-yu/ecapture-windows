/*
 * schannel_hook.dll — companion DLL for eCapture Windows SSPI plaintext capture.
 *
 * Injected into a target process (via eCapture InjectDLL). Hooks
 * sspicli/secur32!EncryptMessage / DecryptMessage, copies plaintext SecBuffers,
 * and streams them to \\.\pipe\ecapture-schannel.
 *
 * Critical implementation notes (amd64):
 *   - Trampoline / detour jumps MUST NOT clobber RAX. EncryptMessage prologue
 *     loads the /GS stack cookie into RAX (mov rax,[rip+…]) and the next
 *     instruction is xor rax,rsp. A "mov rax,imm64; jmp rax" return stub
 *     destroys the cookie and causes AccessViolation (0xC0000005) inside
 *     EncryptMessage — often on the 2nd HTTPS request.
 *   - Use FF 25 00 00 00 00 ; dq abs  (jmp qword ptr [rip+0]) instead.
 *   - Stolen RIP-relative displacements must be rewritten for the trampoline.
 *   - Trampoline memory must be PAGE_EXECUTE_READWRITE (VirtualAlloc).
 *
 * Build (MinGW via clang, from repo root):
 *   clang --target=x86_64-w64-windows-gnu -shared -O2 -DSECURITY_WIN32 -o bin/schannel_hook.dll \
 *       contrib/schannel_hook/schannel_hook.c -lsecur32
 *
 * Protocol (little-endian):
 *   uint32 process_id
 *   uint32 thread_id
 *   uint32 direction   // 0=send(EncryptMessage), 1=recv(DecryptMessage)
 *   uint32 length
 *   uint8  data[length]
 *
 * ARM64 builds are a safe no-op (no inline hook).
 */

#define WIN32_LEAN_AND_MEAN
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sspi.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "ws2_32.lib")

#define PORT_FILE "ecapture_schannel_port.txt"
#define MAX_CAPTURE (1 << 20)
/* jmp qword ptr [rip+0] ; dq target  — does not clobber any GPRs */
#define HOOK_JMP_LEN 14
#define TRAMP_CAP 128

typedef SECURITY_STATUS(WINAPI *EncryptMessage_t)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
typedef SECURITY_STATUS(WINAPI *DecryptMessage_t)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);

static EncryptMessage_t g_orig_encrypt = NULL;
static DecryptMessage_t g_orig_decrypt = NULL;
static BYTE *g_enc_trampoline = NULL;
static BYTE *g_dec_trampoline = NULL;
static CRITICAL_SECTION g_cs;
static SOCKET g_sock = INVALID_SOCKET;
static volatile LONG g_cs_ready = 0;
static volatile LONG g_wsa_ready = 0;

static void debug_log(const char *msg) {
	HANDLE f;
	DWORD w = 0;
	char line[256];
	int n;
	SYSTEMTIME st;
	GetLocalTime(&st);
	n = wsprintfA(line, "%02u:%02u:%02u %s\r\n", st.wHour, st.wMinute, st.wSecond, msg);
	f = CreateFileA("C:\\Users\\Public\\ecapture_hook_debug.log",
			FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f != INVALID_HANDLE_VALUE) {
		WriteFile(f, line, (DWORD)n, &w, NULL);
		CloseHandle(f);
	}
}

static int read_port(void) {
	char path[MAX_PATH];
	char buf[32];
	DWORD n = 0;
	HANDLE f;
	DWORD len;
	int port = 0;
	len = GetTempPathA(MAX_PATH, path);
	if (len == 0 || len > MAX_PATH - 64) {
		return 0;
	}
	lstrcatA(path, PORT_FILE);
	f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (f == INVALID_HANDLE_VALUE) {
		return 0;
	}
	if (!ReadFile(f, buf, sizeof(buf) - 1, &n, NULL) || n == 0) {
		CloseHandle(f);
		return 0;
	}
	CloseHandle(f);
	buf[n] = 0;
	port = atoi(buf);
	return port;
}

static void ensure_sock(void) {
	struct sockaddr_in addr;
	int port;
	int i;
	if (g_sock != INVALID_SOCKET) {
		return;
	}
	if (!g_wsa_ready) {
		WSADATA wsa;
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
			debug_log("WSAStartup failed");
			return;
		}
		InterlockedExchange(&g_wsa_ready, 1);
	}
	for (i = 0; i < 50; i++) {
		port = read_port();
		if (port <= 0 || port > 65535) {
			Sleep(20);
			continue;
		}
		g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (g_sock == INVALID_SOCKET) {
			debug_log("socket() failed");
			return;
		}
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons((u_short)port);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (connect(g_sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
			char msg[64];
			wsprintfA(msg, "tcp connected port=%d", port);
			debug_log(msg);
			return;
		}
		closesocket(g_sock);
		g_sock = INVALID_SOCKET;
		Sleep(20);
	}
	debug_log("tcp connect FAILED");
}

static void send_capture(DWORD direction, const BYTE *data, DWORD len) {
	BYTE hdr[16];
	DWORD pid, tid;
	int sent;

	if (!data || len == 0 || len > MAX_CAPTURE || !g_cs_ready) {
		return;
	}
	EnterCriticalSection(&g_cs);
	ensure_sock();
	if (g_sock == INVALID_SOCKET) {
		LeaveCriticalSection(&g_cs);
		return;
	}
	pid = GetCurrentProcessId();
	tid = GetCurrentThreadId();
	memcpy(hdr + 0, &pid, 4);
	memcpy(hdr + 4, &tid, 4);
	memcpy(hdr + 8, &direction, 4);
	memcpy(hdr + 12, &len, 4);
	sent = send(g_sock, (const char *)hdr, 16, 0);
	if (sent != 16) {
		closesocket(g_sock);
		g_sock = INVALID_SOCKET;
		LeaveCriticalSection(&g_cs);
		return;
	}
	sent = send(g_sock, (const char *)data, (int)len, 0);
	if (sent != (int)len) {
		closesocket(g_sock);
		g_sock = INVALID_SOCKET;
	}
	LeaveCriticalSection(&g_cs);
}

static void capture_buffers(DWORD direction, PSecBufferDesc desc) {
	ULONG i;
	ULONG matched = 0;
	if (!desc || !desc->pBuffers) {
		return;
	}
	for (i = 0; i < desc->cBuffers; i++) {
		PSecBuffer b = &desc->pBuffers[i];
		ULONG typ;
		if (!b || !b->pvBuffer || b->cbBuffer == 0) {
			continue;
		}
		typ = b->BufferType & 0x0FFFFFFFUL;
		/* SECBUFFER_DATA=1; also accept STREAM_* plaintext-bearing layouts. */
		if (typ == 1 || typ == 2 /* TOKEN sometimes carries early data */) {
			send_capture(direction, (const BYTE *)b->pvBuffer, b->cbBuffer);
			matched++;
		}
	}
	if (matched == 0 && desc->cBuffers > 0) {
		char msg[96];
		wsprintfA(msg, "no DATA bufs dir=%u cBuffers=%u type0=%u",
			  direction, desc->cBuffers,
			  desc->pBuffers[0].BufferType & 0x0FFFFFFFUL);
		debug_log(msg);
	}
}

static SECURITY_STATUS WINAPI hook_EncryptMessage(PCtxtHandle ctx, ULONG qop, PSecBufferDesc msg, ULONG seq) {
	static volatile LONG once = 0;
	if (InterlockedCompareExchange(&once, 1, 0) == 0) {
		debug_log("EncryptMessage hook hit");
	}
	capture_buffers(0, msg);
	if (!g_orig_encrypt) {
		return SEC_E_INTERNAL_ERROR;
	}
	return g_orig_encrypt(ctx, qop, msg, seq);
}

static SECURITY_STATUS WINAPI hook_DecryptMessage(PCtxtHandle ctx, PSecBufferDesc msg, ULONG seq, PULONG qop) {
	SECURITY_STATUS st;
	if (!g_orig_decrypt) {
		return SEC_E_INTERNAL_ERROR;
	}
	st = g_orig_decrypt(ctx, msg, seq, qop);
	if (st == SEC_E_OK) {
		capture_buffers(1, msg);
	}
	return st;
}

#if defined(__x86_64__) || defined(_M_X64)

typedef struct {
	int len;
	int rip_disp_off; /* byte offset of disp32 within insn, or -1 */
	int rel_branch;
} x64_insn;

static int decode_x64_insn(const BYTE *p, x64_insn *out) {
	const BYTE *start = p;
	BYTE pref = 0;
	BYTE rex = 0;
	int i;
	BYTE op, op2 = 0;
	int has_modrm = 0;
	int imm = 0;

	out->len = 0;
	out->rip_disp_off = -1;
	out->rel_branch = 0;

	for (i = 0; i < 15; i++) {
		BYTE c = *p;
		if (c == 0xF0 || c == 0xF2 || c == 0xF3 || c == 0x66 || c == 0x67 ||
		    c == 0x2E || c == 0x36 || c == 0x3E || c == 0x26 || c == 0x64 || c == 0x65) {
			pref = c;
			p++;
			continue;
		}
		if ((c & 0xF0) == 0x40) {
			rex = c;
			p++;
			continue;
		}
		break;
	}

	op = *p++;

	if (op == 0x0F) {
		op2 = *p++;
		if (op2 >= 0x80 && op2 <= 0x8F) {
			out->rel_branch = 1;
			imm = 4;
		} else {
			has_modrm = 1;
		}
	} else if (op == 0xE8 || op == 0xE9) {
		out->rel_branch = 1;
		imm = 4;
	} else if (op == 0xEB || (op >= 0x70 && op <= 0x7F)) {
		out->rel_branch = 1;
		imm = 1;
	} else if (op == 0xC2) {
		imm = 2;
	} else if (op == 0xC3 || op == 0xCB || op == 0xCC || op == 0x90 ||
		   (op >= 0x50 && op <= 0x5F)) {
		/* push/pop / ret / nop / int3 */
	} else if (op == 0x6A) {
		imm = 1;
	} else if (op == 0x68) {
		imm = 4;
	} else if ((op & 0xF8) == 0xB8) {
		imm = (rex & 0x08) ? 8 : ((pref == 0x66) ? 2 : 4);
	} else if ((op & 0xF8) == 0xB0) {
		imm = 1;
	} else if (op == 0x83 || op == 0xC0 || op == 0xC1) {
		has_modrm = 1;
		imm = 1;
	} else if (op == 0x81) {
		has_modrm = 1;
		imm = (pref == 0x66) ? 2 : 4;
	} else if (op == 0x69) {
		has_modrm = 1;
		imm = (pref == 0x66) ? 2 : 4;
	} else if (op == 0x6B || op == 0xC6) {
		has_modrm = 1;
		imm = 1;
	} else if (op == 0xC7) {
		has_modrm = 1;
		imm = (pref == 0x66) ? 2 : 4;
	} else if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D || op == 0x25 ||
		   op == 0x2D || op == 0x35 || op == 0x3D) {
		imm = (pref == 0x66) ? 2 : 4;
	} else if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C || op == 0x24 ||
		   op == 0x2C || op == 0x34 || op == 0x3C || op == 0xA8) {
		imm = 1;
	} else if (op == 0xFF || op == 0x8F || op == 0x80 || op == 0x84 || op == 0x85 ||
		   op == 0x86 || op == 0x87 || op == 0x88 || op == 0x89 || op == 0x8A ||
		   op == 0x8B || op == 0x8C || op == 0x8D || op == 0x8E || op == 0x01 ||
		   op == 0x03 || op == 0x09 || op == 0x0B || op == 0x11 || op == 0x13 ||
		   op == 0x19 || op == 0x1B || op == 0x21 || op == 0x23 || op == 0x29 ||
		   op == 0x2B || op == 0x31 || op == 0x33 || op == 0x39 || op == 0x3B ||
		   op == 0x63 || op == 0xD0 || op == 0xD1 || op == 0xD2 || op == 0xD3 ||
		   op == 0xF6 || op == 0xF7 || op == 0xFE) {
		has_modrm = 1;
	} else {
		return 0;
	}

	if (has_modrm) {
		BYTE modrm = *p++;
		BYTE mod = (BYTE)(modrm >> 6);
		BYTE rm = (BYTE)(modrm & 7);
		if (mod != 3 && rm == 4) {
			BYTE sib = *p++;
			BYTE base = (BYTE)(sib & 7);
			if (mod == 0 && base == 5) {
				p += 4; /* abs [disp32] */
			}
		} else if (mod == 0 && rm == 5) {
			out->rip_disp_off = (int)(p - start);
			p += 4;
		}
		if (mod == 1) {
			p += 1;
		} else if (mod == 2) {
			p += 4;
		}
	}

	p += imm;
	out->len = (int)(p - start);
	if (out->len <= 0 || out->len > 15) {
		return 0;
	}
	(void)op2;
	return 1;
}

/* Register-preserving absolute jump (14 bytes). */
static void emit_abs_jmp(BYTE *dst, UINT_PTR target) {
	dst[0] = 0xFF; /* jmp qword ptr [rip+0] */
	dst[1] = 0x25;
	dst[2] = 0x00;
	dst[3] = 0x00;
	dst[4] = 0x00;
	dst[5] = 0x00;
	memcpy(dst + 6, &target, sizeof(target));
}

/*
 * Allocate executable memory within ±~1.5GB of target so rewritten
 * RIP-relative displacements still fit in a signed 32-bit offset.
 * A naive VirtualAlloc(NULL) often lands >2GB away on x64 Windows and
 * silently breaks /GS cookie loads in EncryptMessage.
 */
static BYTE *alloc_trampoline_near(void *target) {
	SYSTEM_INFO si;
	UINT_PTR t = (UINT_PTR)target;
	UINT_PTR gran;
	UINT_PTR limit = 0x60000000ULL;
	UINT_PTR minAddr, maxAddr, lo, hi, base, off;
	BYTE *p;

	GetSystemInfo(&si);
	gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
	minAddr = (UINT_PTR)si.lpMinimumApplicationAddress;
	maxAddr = (UINT_PTR)si.lpMaximumApplicationAddress;
	lo = (t > limit) ? (t - limit) : minAddr;
	hi = (t + limit < t) ? maxAddr : (t + limit); /* overflow guard */
	if (hi > maxAddr) {
		hi = maxAddr;
	}
	if (lo < minAddr) {
		lo = minAddr;
	}
	base = t & ~(gran - 1);

	for (off = 0; off < limit; off += gran) {
		if (base >= lo + off) {
			p = (BYTE *)VirtualAlloc((LPVOID)(base - off), TRAMP_CAP,
						 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (p) {
				return p;
			}
		}
		if (off != 0 && base + off < hi) {
			p = (BYTE *)VirtualAlloc((LPVOID)(base + off), TRAMP_CAP,
						 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (p) {
				return p;
			}
		}
	}
	return NULL;
}

static int build_trampoline(BYTE *tramp, size_t tramp_size, BYTE *src, int *stolen_out) {
	int stolen = 0;
	int off = 0;

	while (stolen < HOOK_JMP_LEN) {
		x64_insn insn;
		INT64 delta;
		if (!decode_x64_insn(src + stolen, &insn) || insn.len <= 0) {
			return -1;
		}
		if (insn.rel_branch) {
			return -2;
		}
		if (off + insn.len + HOOK_JMP_LEN > (int)tramp_size) {
			return -3;
		}
		memcpy(tramp + off, src + stolen, (size_t)insn.len);
		if (insn.rip_disp_off >= 0) {
			INT32 old_disp;
			UINT_PTR abs_target;
			UINT_PTR new_next;
			INT32 new_disp;
			memcpy(&old_disp, tramp + off + insn.rip_disp_off, sizeof(old_disp));
			abs_target = (UINT_PTR)(src + stolen + insn.len) + (INT32)old_disp;
			new_next = (UINT_PTR)(tramp + off + insn.len);
			delta = (INT64)abs_target - (INT64)new_next;
			if (delta != (INT32)delta) {
				return -4; /* trampoline too far for RIP-relative */
			}
			new_disp = (INT32)delta;
			memcpy(tramp + off + insn.rip_disp_off, &new_disp, sizeof(new_disp));
		}
		off += insn.len;
		stolen += insn.len;
	}

	/* Steal /GS cookie finalize if present so RAX is not live across jmp-back:
	 *   xor rax, rsp ; mov [rsp+imm8], rax
	 */
	{
		x64_insn i1, i2;
		if (decode_x64_insn(src + stolen, &i1) && i1.len == 3 &&
		    src[stolen] == 0x48 && src[stolen + 1] == 0x33 && src[stolen + 2] == 0xC4 &&
		    decode_x64_insn(src + stolen + 3, &i2) && i2.len == 5 &&
		    src[stolen + 3] == 0x48 && src[stolen + 4] == 0x89 &&
		    off + 3 + 5 + HOOK_JMP_LEN <= (int)tramp_size) {
			memcpy(tramp + off, src + stolen, 8);
			off += 8;
			stolen += 8;
		}
	}

	emit_abs_jmp(tramp + off, (UINT_PTR)(src + stolen));
	*stolen_out = stolen;
	return 0;
}

static int install_inline_hook(void *target, void *detour, BYTE **tramp_out, void **orig_out) {
	BYTE *src = (BYTE *)target;
	BYTE *tramp;
	int stolen = 0;
	DWORD oldProt = 0;
	int i;
	int brc;

	tramp = alloc_trampoline_near(src);
	if (!tramp) {
		return -1;
	}
	memset(tramp, 0xCC, TRAMP_CAP);

	brc = build_trampoline(tramp, TRAMP_CAP, src, &stolen);
	if (brc != 0 || stolen < HOOK_JMP_LEN) {
		VirtualFree(tramp, 0, MEM_RELEASE);
		return -2;
	}

	if (!VirtualProtect(src, (SIZE_T)stolen, PAGE_EXECUTE_READWRITE, &oldProt)) {
		VirtualFree(tramp, 0, MEM_RELEASE);
		return -3;
	}

	emit_abs_jmp(src, (UINT_PTR)detour);
	for (i = HOOK_JMP_LEN; i < stolen; i++) {
		src[i] = 0x90;
	}

	VirtualProtect(src, (SIZE_T)stolen, oldProt, &oldProt);
	FlushInstructionCache(GetCurrentProcess(), src, (SIZE_T)stolen);
	FlushInstructionCache(GetCurrentProcess(), tramp, (SIZE_T)TRAMP_CAP);

	*tramp_out = tramp;
	*orig_out = tramp;
	return 0;
}

static void install_hooks(void) {
	HMODULE secur32 = LoadLibraryA("secur32.dll");
	FARPROC enc;
	FARPROC dec;
	void *orig_enc = NULL;
	void *orig_dec = NULL;

	if (!secur32) {
		return;
	}
	enc = GetProcAddress(secur32, "EncryptMessage");
	dec = GetProcAddress(secur32, "DecryptMessage");
	if (!enc || !dec) {
		return;
	}
	if (install_inline_hook((void *)enc, (void *)hook_EncryptMessage, &g_enc_trampoline, &orig_enc) == 0) {
		g_orig_encrypt = (EncryptMessage_t)orig_enc;
		debug_log("EncryptMessage hooked OK");
	} else {
		debug_log("EncryptMessage hook FAILED");
	}
	if (install_inline_hook((void *)dec, (void *)hook_DecryptMessage, &g_dec_trampoline, &orig_dec) == 0) {
		g_orig_decrypt = (DecryptMessage_t)orig_dec;
		debug_log("DecryptMessage hooked OK");
	} else {
		debug_log("DecryptMessage hook FAILED");
	}
}

#else /* !x86_64 */

static void install_hooks(void) {
	/* ARM64: not implemented — DLL is a no-op. */
}

#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
	(void)reserved;
	if (reason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hModule);
		InitializeCriticalSection(&g_cs);
		InterlockedExchange(&g_cs_ready, 1);
		install_hooks();
	} else if (reason == DLL_PROCESS_DETACH) {
		InterlockedExchange(&g_cs_ready, 0);
		if (g_sock != INVALID_SOCKET) {
			closesocket(g_sock);
			g_sock = INVALID_SOCKET;
		}
		if (g_wsa_ready) {
			WSACleanup();
			InterlockedExchange(&g_wsa_ready, 0);
		}
		DeleteCriticalSection(&g_cs);
		/* Leave hooks in place on unload; tearing them down safely needs
		 * thread suspension. Process exit reclaims trampoline pages. */
	}
	return TRUE;
}
