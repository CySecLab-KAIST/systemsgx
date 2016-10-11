#include <string.h>
#include <stdio.h>
#include "openssl/evp.h"
#include "openssl/modes.h"

#include "cpu.h"
#include "sgx.h"
#include "sgx-utils.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "sgx-dbg.h"
#include "exec/cpu-all.h"
#include "sgx-perf.h"

#include "polarssl/sha256.h"
#include "polarssl/rsa.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/sha1.h"
#include "polarssl/aes_cmac128.h"

static qeid_t qenclaves[MAX_ENCLAVES];

/**
 *  SGX Global Data Structures
 */
static epcm_entry_t epcm[NUM_EPC];
static epc_map * enclaveTrackEntry = NULL;      // Tracking pointers For enclaves
static eid_einit_t * entry_eid = NULL;
static uint64_t EPC_BaseAddr;
static uint64_t EPC_EndAddr;
// Collaborate them
static bool enclave_init = false;
//static bool enclave_Access = false;
static bool einit_Success = false;
//static bool enclave_Exit = false;
static int32_t curr_Eid = -1;

static uint64_t enclave_ssa_base;

static uint8_t process_priv_key[DEVICE_KEY_LENGTH];
static uint8_t process_pub_key[DEVICE_KEY_LENGTH];

typedef struct {
    bool read_check;
    bool write_check;
    bool read_perm;
    bool write_perm;
} perm_check_t;

typedef enum {
    eenter,
    eresume,
    none,
} op_type_t;

// why?
op_type_t operation = none;

// Data structure & Functions for EWB/ELD instruction
static const unsigned char gcm_key[] = { 
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
}; //size 32 byte = 256 bit

static
void handleError(const char *errMsg)
{
    sgx_dbg(trace, "%s", errMsg);
    exit(-1);
}

static
int encrypt_epc(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
            int aad_len, const unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    sgx_dbg(trace, "AES GCM Encrypt----------");
    sgx_dbg(trace, "IV");
    BIO_dump_fp(stderr, iv, 12);
    sgx_dbg(trace, "Key");
    BIO_dump_fp(stderr, key, 32);
    sgx_dbg(trace, "Plaintext");
    BIO_dump_fp(stderr, plaintext, 64);
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleError("Context Creation Error");
    }

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        handleError("EVP Init Error");
    }

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)){
        handleError("Context Control Error");
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)){
        handleError("Key & IV Init Error");
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        handleError("Aad Addtion Error !!!");
    }
    sgx_dbg(trace, "len after encryption is %d, and aad_len is %d", len, aad_len);

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
        handleError("Encryption Error");
    }
    ciphertext_len = len;
    sgx_dbg(trace, "Ciphertext");
    BIO_dump_fp(stderr, ciphertext, 64);

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
        handleError("Finalize Error");
    }
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)){
        handleError("Getting Tag Error");
    }

    sgx_dbg(trace,"Tag");
    BIO_dump_fp(stderr, tag, 16);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    sgx_dbg(trace,"encrypt_epc finishes well");

    return ciphertext_len;
}

static
int decrypt_epc(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
            int aad_len, unsigned char *tag, const unsigned char *key, unsigned char *iv,
            unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    sgx_dbg(trace, "AES GCM Decrypt----------");
    sgx_dbg(trace, "Tag");
    BIO_dump_fp(stderr, tag, 16);
    sgx_dbg(trace, "Ciphertext");
    BIO_dump_fp(stderr, ciphertext, 64);
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){ 
        handleError("Context Creation Error");
    }

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)){
        handleError("EVIP Decrypt Init Error");
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)){
        handleError("Context Control Error");
    }

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)){
        handleError("Key & IV Init Error");
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        //cch: if this error happen, please update openssl to the latest version
        handleError("Aad Addtion Error");
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        handleError("Decryption Error");
    }
    plaintext_len = len;
    sgx_dbg(trace, "Plaintext");
    BIO_dump_fp(stderr, plaintext, 64);
    sgx_dbg(trace, "Key");
    BIO_dump_fp(stderr, key, 32);
    sgx_dbg(trace, "IV");
    BIO_dump_fp(stderr, iv, 12);

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)){
        handleError("Setting Tag Error");
    }

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    ERR_print_errors_fp(stderr);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        /* Success */
        plaintext_len += len;
        sgx_dbg(trace, "decrypt_epc finishes well");
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}


// A helper function to intialize attributes_t
static inline
attributes_t attr_create(uint64_t a1, uint64_t a2)
{
    attributes_t attr;
    memcpy(&attr, &a1, sizeof(uint64_t));
    memcpy((char *)(&attr) + sizeof(uint64_t), &a2, sizeof(uint64_t));
    return attr;
}

// A helper function to mask attributes. Returns *attr1 & *attr2
static inline
attributes_t attr_mask(attributes_t* attr1, attributes_t* attr2)
{
    uint64_t a1, a2;
    a1 = ((uint64_t *)attr1)[0] & ((uint64_t *)attr2)[0];
    a2 = ((uint64_t *)attr1)[1] & ((uint64_t *)attr2)[1];
    return attr_create(a1, a2);
}

// A helper function for computing bitwise OR of two masks, returns *m1 | *m2
static inline
attributes_t attr_mask_combine(attributes_t* attr1, attributes_t* attr2)
{
    uint64_t a1, a2;
    a1 = ((uint64_t *)attr1)[0] | ((uint64_t *)attr2)[0];
    a2 = ((uint64_t *)attr1)[1] | ((uint64_t *)attr2)[1];
    return attr_create(a1, a2);
}

// Mask
/*
static
uint64_t mask(uint64_t mem_addr, uint64_t page_size)
{
    return (mem_addr & ~(page_size - 1));
}
*/

// Reserved Zero-Check
static
void is_reserved_zero(void *addr, uint32_t bytes, CPUX86State *env)
{
    assert(addr);
    assert(env);

    unsigned char *temp_addr = (unsigned char *)malloc(bytes);
    memset(temp_addr, 0, bytes);

    if (memcmp(temp_addr, addr, bytes) != 0)
    {
        sgx_msg(warn, "Reserved zero check fail");
        raise_exception(env, EXCP0D_GPF);
    }
}

static
bool is_enclave_initialized(void)
{
    // Intercepting Memory access only if ECREATE has been invoked
    if (enclave_init) {
        return true;
    }
    return false;
}

// Check if mem_addr is within the current enclave
static
bool is_within_enclave(CPUX86State *env, uint64_t mem_addr)
{
    return ((mem_addr >= env->cregs.CR_ELRANGE[0]) &&
         (mem_addr <= (env->cregs.CR_ELRANGE[0] + env->cregs.CR_ELRANGE[1])));
}

static 
bool is_within_user(uint64_t mem_addr)
{
    return ((mem_addr >= 0x0) && 
            (mem_addr <= 0x7fffffffffff));
}


// Check if mem_addr is in EPC
static
bool is_within_epc(uint64_t mem_addr)
{
    if ((mem_addr > (EPC_BaseAddr)) && (mem_addr < (EPC_EndAddr))) {
        return true;
    }
    return false;
}

uint64_t return_hostaddr(CPUX86State *env, uint64_t guestaddr){ 
    int page_index;
    int mmu_idx;
    int temp;
    int size = 8; 
    page_index = (guestaddr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = cpu_mmu_index(env);//CPU_MMU_INDEX; 
    uint64_t hostaddr;

    if (unlikely(env->tlb_table[mmu_idx][page_index].addr_read !=
                 (guestaddr & (TARGET_PAGE_MASK | (size - 1))))) {    
       temp = glue(glue(helper_ld, q), _mmu)(env, guestaddr, mmu_idx); 
       hostaddr = guestaddr + env->tlb_table[mmu_idx][page_index].addend; 
    }   
    else{
       hostaddr = guestaddr + env->tlb_table[mmu_idx][page_index].addend;
    }   

    return hostaddr;
}

// Check if mem_addr is in EPC
static
bool linaddr_is_within_epc(CPUX86State *env, uint64_t mem_addr)
{
    sgx_dbg(mtrace, "linaddr_is_within_epc entry point mem_addr: %p", mem_addr);
    int16_t found = 0;
    int i;
    uint64_t hostaddr = return_hostaddr(env, mem_addr);

    sgx_dbg(mtrace, "guestaddr is %p, hostaddr is %p", mem_addr, hostaddr);

    if((epcm[0].epcHostAddress <= hostaddr) 
          && (hostaddr < epcm[NUM_EPC-1].epcHostAddress + PAGE_SIZE)) {
        found = 1;
    }

    if (found == 0) {
        sgx_dbg(mtrace, "linaddr is not within epc");
        return false;
    }

    return true;
}

// InEPC check
static
void check_within_epc(void *page_addr, CPUX86State *env)
{
    assert(page_addr);
    assert(env);

    if (!is_within_epc((uint64_t)page_addr)) {
        sgx_msg(warn, "Page is not in EPC");
        raise_exception(env, EXCP0D_GPF);
    }
}

// InEPC check
static
void check_linaddr_within_epc(void *page_addr, CPUX86State *env)
{
    assert(page_addr);
    assert(env);

    if (!linaddr_is_within_epc(env, (uint64_t)page_addr)) {
        sgx_msg(warn, "Page is not in EPC");
        raise_exception(env, EXCP0D_GPF);
    }    
}

static
bool is_within_same_epc(void *target_addr1, void *target_addr2, CPUX86State *env)
{
    check_within_epc(target_addr1, env);
    check_within_epc(target_addr2, env);

    int i = 0, target_index1 = 0, target_index2 = 0 ;
    int start_addr, end_addr;

    start_addr = EPC_BaseAddr;
    end_addr = EPC_BaseAddr + PAGE_SIZE;
    for (i = 0 ; i < NUM_EPC; i++) {
       if (target_index1 && target_index2) //found two indices.
           break;
       if((!target_index1) && ((uintptr_t)target_addr1 > start_addr) &&
		  ((uintptr_t)target_addr1 < end_addr)) {
           target_index1 = i;
       }
       if((!target_index2) && ((uintptr_t)target_addr2 > start_addr) &&
		  ((uintptr_t)target_addr2 < end_addr)) {
           target_index2 = i;
       }
       start_addr += PAGE_SIZE;
       end_addr += PAGE_SIZE;
    }

    return (target_index1 == target_index2);
}

// Canonical Check
static
void is_canonical(uint64_t addr, CPUX86State *env)
{
    /*assert(env);

    // Canonical form : bit 48-63 is same as bit 47
    uint64_t MASK_48_63 = 0xFFFF800000000000;
    uint64_t MASK_47 = 0x0000400000000000;

    if ((addr & MASK_47) == MASK_47) {
        if ((addr & MASK_48_63) != MASK_48_63) {
            sgx_msg(warn, "canonical check fail");
            raise_exception(env, EXCP0D_GPF);
        }
    } else {
        if ((addr & MASK_48_63) != 0) {
            sgx_msg(warn, "canonical check fail");
            raise_exception(env, EXCP0D_GPF);
        }
    }*/
}

// check whether valid field of epcm is 1
static
void epcm_valid_check(epcm_entry_t *epcm_entry, CPUX86State *env)
{
    assert(epcm_entry);
    assert(env);

    if (epcm_entry->valid == 1) {
        sgx_msg(warn, "epcm is already valid");
        raise_exception(env, EXCP0D_GPF);
    }
}

// check whether valid field of epcm is 0
static
void epcm_invalid_check(epcm_entry_t *epcm_entry, CPUX86State *env)
{
    assert(epcm_entry);
    assert(env);

    if (epcm_entry->valid == 0) {
        sgx_msg(warn, "epcm is invalid");
        raise_exception(env, EXCP0D_GPF);
    }
}

// check whether valid field of epcm is 1
static
void epcm_blocked_check(epcm_entry_t *epcm_entry, CPUX86State *env)
{
    assert(epcm_entry);
    assert(env);

    if (epcm_entry->blocked == 1) {
        sgx_msg(warn, "epcm is blocked");
        raise_exception(env, EXCP0D_GPF);
    }
}

// check page_type field of epcm
static
void epcm_page_type_check(epcm_entry_t *epcm_entry, uint8_t PT,
                          CPUX86State *env)
{
    assert(epcm_entry);
    assert(env);

    if (epcm_entry->page_type != PT) {
        sgx_msg(warn, "Page type is incorrect");
        raise_exception(env, EXCP0D_GPF);
    }
}

// check enclave_addr field of epcm
static
void epcm_enclave_addr_check(epcm_entry_t *epcm_entry, uint64_t addr,
                             CPUX86State *env)
{
    assert(epcm_entry);
    assert(env);

    if (epcm_entry->enclave_addr != addr) {
        sgx_dbg(trace, "eclaveAddr in epcm is %p, addr is %p",(void *)epcm_entry->enclave_addr, (void *)addr);
        sgx_msg(warn, "enclaveAddr is incorrect");
        raise_exception(env, EXCP0D_GPF);
    }
}

// check enclaveSECS field of epcm
static
void epcm_enclaveSECS_check(epcm_entry_t *epcm_entry, uint64_t enclaveSECS,
                            CPUX86State *env)
{
    assert(epcm_entry);
    assert(env);

    if (epcm_entry->enclave_secs != enclaveSECS) {
        sgx_msg(warn, "SECS of page is incorrect");
        sgx_dbg(trace, "Enclave SECS: %"PRIx64"  provided SECS: %"PRIx64"",
                enclaveSECS, epcm_entry->enclave_secs);
        raise_exception(env, EXCP0D_GPF);
    }
}

// check several fields of epcm
static
void epcm_field_check(epcm_entry_t *epcm_entry, uint64_t enclave_addr,
                      uint8_t page_type, uint64_t enclaveSECS, CPUX86State *env)
{
    assert(epcm_entry);
    assert(env);

    epcm_enclave_addr_check(epcm_entry, enclave_addr, env);
    epcm_page_type_check(epcm_entry, page_type, env);
    epcm_enclaveSECS_check(epcm_entry, enclaveSECS, env);
}

// Mark the ssa base
static
void set_ssa_base(void)
{
    enclave_ssa_base = NUM_EPC;
}

// Update the SSA Base
// Unused.
#if 0
static
void update_ssa_base(void)
{
    enclave_ssa_base = (enclave_ssa_base < NUM_EPC) ?
                       enclave_ssa_base + 1 : NUM_EPC;
}
#endif

static
void xsave(bool mode, uint64_t xfrm, uint64_t page)
{

}

static
void clearBytes(uint64_t *page, uint8_t index)
{

}

static
void assignBits(uint64_t *page, secs_t *secs)
{

}

static
void saveState(gprsgx_t* page, CPUX86State *env)
{
    sgx_dbg(trace, "State will be stored in %p", (void *)page);
    sgx_dbg(trace, "State is allocated in tmp_page");
    page->rax = env->regs[R_EAX];
    sgx_dbg(trace, "EAX saved will be %p", (void *)page->rax);
    page->rbx = env->regs[R_EBX];
    sgx_dbg(trace, "EBX saved will be %p", (void *)page->rbx);
    page->rcx = env->regs[R_ECX];
    sgx_dbg(trace, "ECX saved will be %p", (void *)page->rcx);
    page->rdx = env->regs[R_EDX];
    sgx_dbg(trace, "EDX saved will be %p", (void *)page->rdx);
    page->rsp = env->regs[R_ESP];
    sgx_dbg(trace, "ESP saved will be %p", (void *)page->rsp);
    page->rbp = env->regs[R_EBP];
    sgx_dbg(trace, "EBP saved will be %p", (void *)page->rbp);
    page->rsi = env->regs[R_ESI];
    sgx_dbg(trace, "ESI saved will be %p", (void *)page->rsi);
    page->rdi = env->regs[R_EDI];
    sgx_dbg(trace, "EDI saved will be %p", (void *)page->rdi);
    page->rflags = env->eflags;
    page->rip = env->eip; 
    sgx_dbg(trace, "EIP saved will be %p", (void *)page->rip);
    sgx_dbg(trace, "State is saved in tmp_page");
}

static
void restoreGPRs(gprsgx_t *page, CPUX86State *env)
{
    sgx_dbg(trace, "State in %p will be restored", (void *)page);
    env->regs[R_EAX] = page->rax;
    sgx_dbg(trace, "EAX restored will be %p", (void *)page->rax);
    env->regs[R_EBX] = page->rbx;
    sgx_dbg(trace, "EBX restored will be %p", (void *)page->rbx);
    env->regs[R_ECX] = page->rcx;
    sgx_dbg(trace, "ECX restored will be %p", (void *)page->rcx);
    env->regs[R_EDX] = page->rdx;
    sgx_dbg(trace, "EDX restored will be %p", (void *)page->rdx);
    env->regs[R_ESP] = page->rsp;
    sgx_dbg(trace, "ESP restored will be %p", (void *)page->rsp);
    env->regs[R_EBP] = page->rbp;
    sgx_dbg(trace, "EBP restored will be %p", (void *)page->rbp);
    env->regs[R_ESI] = page->rsi;
    sgx_dbg(trace, "ESP restored will be %p", (void *)page->rsi);
    env->regs[R_EDI] = page->rdi;
    sgx_dbg(trace, "EDI restored will be %p", (void *)page->rdi);
    /* FIXME: tf to removed*/
    env->eflags = page->rflags;
}

static
bool checkSECSModification(void)
{
    return false;
}

static
bool checkReservedSpace(sigstruct_t sig, CPUX86State *env)
{
    // Check if Reserved space is filled with 0's
    is_reserved_zero(sig.reserved1, sizeof(((sigstruct_t *)0)->reserved1), env);
    is_reserved_zero(sig.reserved2, sizeof(((sigstruct_t *)0)->reserved2), env);
    is_reserved_zero(sig.reserved3, sizeof(((sigstruct_t *)0)->reserved3), env);
    is_reserved_zero(sig.reserved4, sizeof(((sigstruct_t *)0)->reserved4), env);

    return true;
}

static
bool checkField(sigstruct_t sig, const char* key, const char *field)
// Will be modified
{
    uint32_t fieldNo = INT_MAX;
    uint32_t len = strlen(field);
    uint32_t keyLen = strlen(key);
    uint8_t *header = NULL;

    if (!strncmp(field, "HEADER", min(len, 7))) {
        header = sig.header;
        fieldNo = 1;
    } else if (!strncmp( field, "HEADER2", min(len, 8))) {
        header = sig.header2;
        fieldNo = 3;
    } else {
        return false;
    }

    // Assuming the information is stored lower byte first
    //  into the header field and compare accordingly
    uint8_t iter;
    switch(fieldNo) {
        case 1:
        case 3: {
            for (iter = 0; iter < keyLen; iter += 2) {
                if (sig.header[iter]) {
                    uint8_t lnibble = (uint8_t)key[iter];
                    uint8_t hnibble = (uint8_t)key[iter+1];

                    uint8_t byte = header[iter/2];
                    if (((byte & 0x0F) == lnibble) &&
                        (((byte & 0xF0) >> 4) == hnibble)) {
                        return true;
                    }
                }
            }
            return false;
        }
        default :
            break;
    }
    return false;
}

static
bool checkSigStructField(sigstruct_t sig, CPUX86State *env)
{
    const char header[16] = SIG_HEADER1;
    const char header2[16] = SIG_HEADER2;

    if (!checkField(sig, header, "HEADER") ||
        ((sig.vendor != 0) && (sig.vendor != 0x00008086)) ||
        (!checkField(sig, header2, "HEADER2"))  ||
        ((sig.exponent != 0x00000003) || !checkReservedSpace(sig, env))) {
        return false;
    }
    return true;
}

static
uint64_t compute_xsave_frame_size( CPUX86State *env, attributes_t attributes) {
    uint64_t offset = 576;
//    uint64_t tmp_offset;
    uint64_t size_last_x = 0;
//    uint32_t eax, ebx, ecx, edx;
//    uint64_t x;

    /*
    for( x = 2; x < 63; x++ )
    {
        if ( (attributes.xfrm & (1 << x)) != 0 )
        {
                cpu_x86_cpuid(env, 0x0D, (attributes.xfrm & (1 << x)), &eax, &ebx, &ecx, &edx);
                tmp_offset = ebx;
        if (tmp_offset >= (offset + size_last_x))
        {
            offset = tmp_offset;
                        cpu_x86_cpuid(env, 0x0D, (attributes.xfrm & (1 << x)), &eax, &ebx, &ecx, &edx);
            size_last_x = eax;
                }
        }
    }
    */
    return (offset + size_last_x);
}

// Searches EPCM for effective address
static
uint16_t epcm_search(void *addr, CPUX86State *env)
{

    assert(addr);
    assert(env);

    uint16_t i;
    int16_t index = -1;

    for (i = 0; i < NUM_EPC; i ++) {
        // Can be in between page addresses. for example: EEXTEND : 256 chunks && EWB : Version Array (VA)
        if ((epcm[i].epcPageAddress <= (uint64_t)addr)
                && ((uint64_t)addr < epcm[i].epcPageAddress + PAGE_SIZE)) {
            index = i;
            break;
        }
    }

    if (index == -1) {
        sgx_dbg(warn, "Fail to get epcm index addr: %lx", addr);
        raise_exception(env, EXCP0D_GPF);
    }

    return (uint16_t)index;
}

// Searches EPCM for linear address
static
uint16_t epcm_linsearch(void *addr, CPUX86State *env)
{

    assert(addr);
    assert(env);

    uint16_t i;
    int16_t index = -1;
    uint64_t hostaddr = return_hostaddr(env, addr);

    for (i = 0; i < NUM_EPC; i ++) {
        // Can be in between page addresses. for example: EEXTEND : 256 chunks && EWB : Version Array (VA)
        if ((epcm[i].epcHostAddress <= hostaddr) 
                && (hostaddr < epcm[i].epcHostAddress + PAGE_SIZE)) {
            index = i;
            break;
        }        
    }        

    if (index == -1) {
        sgx_dbg(warn, "Fail to get epcm index addr: %lx", addr);
        raise_exception(env, EXCP0D_GPF);
    }        

    return (uint16_t)index;
}


// Set fields of epcm_entry
static
void set_epcm_entry(epcm_entry_t *epcm_entry, bool valid, bool read, bool write,
                    bool execute, bool blocked, uint8_t pt, uint64_t secs,
                    uint64_t addr)
{
    assert(epcm_entry);

    epcm_entry->valid        = valid;
    epcm_entry->read         = read;
    epcm_entry->write        = write;
    epcm_entry->execute      = execute;
    epcm_entry->blocked      = blocked;
    epcm_entry->page_type    = pt;
    epcm_entry->enclave_secs = secs;
    epcm_entry->enclave_addr = addr;
}

// Check within DS Segment
static
void checkWithinDSSegment(CPUX86State *env, uint64_t addr)
{
    assert(env);

    if (!((env->segs[R_DS].base <= addr)
            && (env->segs[R_DS].base + env->segs[R_DS].limit >= addr))) {
        sgx_msg(warn, "addr is not in DSSegment");
        raise_exception(env, EXCP0D_GPF);
    }
}

// Check reserved bit
static
void checkReservedBits(const uint64_t *addr, const uint64_t mask,
                       CPUX86State *env)
{
    assert(addr);
    assert(env);

    if ((*addr & mask) != 0) {
        sgx_msg(warn, "Reserved bit is not zero");
        raise_exception(env, EXCP0D_GPF);
    }
}

static
bool checkEINIT(uint64_t eid)
{
    eid_einit_t *temp = entry_eid;
    while (temp != NULL) {
        if (temp->eid == eid)
            return true;
        temp = temp->next;
    }
    return false;
}

static
void markEnclave(uint64_t eid)
{
    eid_einit_t *temp;
    if ((temp = (eid_einit_t *) malloc (sizeof (eid_einit_t))) == NULL) {
        sgx_msg(warn, "no more memory");
        return;
    } else {
        temp->eid = eid;
        temp->next = entry_eid;
        entry_eid = temp;
    }
}

// Check whether eid is new(newly allocted enclave) or not
static
bool checkEnclaveID (uint64_t eid)
{
    epc_map *tmp_map = enclaveTrackEntry;
    epc_map *prev = NULL;

    while (tmp_map != NULL) {
        if (tmp_map->eid == eid) {
            if (prev != NULL) {
                prev->next = tmp_map->next;
                tmp_map->next = enclaveTrackEntry;
                enclaveTrackEntry = tmp_map;
            }
            return true;
        }
        prev = tmp_map;
        tmp_map = tmp_map->next;
    }
    return false;
}

static
bool removeEnclaveEntry (secs_t *secs)
{
    uint64_t eid = secs->eid_reserved.eid_pad.eid;
    bool isPresent = checkEnclaveID(eid);
    if (isPresent ) {
        enclaveTrackEntry->active = 0;
        return true;
    }
    return false;
}

static
secinfo_flags_t cpu_load_si_flags(CPUX86State *env, secinfo_t *si)
{
    target_ulong addr = (target_ulong)si + offsetof(secinfo_t, flags);
    uint64_t temp = cpu_ldq_data(env, addr);
    secinfo_flags_t tmp_secinfo_flags_t;
    memcpy(&tmp_secinfo_flags_t, &temp, sizeof(secinfo_flags_t));
    return tmp_secinfo_flags_t;
}

static
void *cpu_load_si_reserved(CPUX86State *env, secinfo_t *si)
{
    target_ulong addr = (target_ulong)si + offsetof(secinfo_t, reserved);
    void *reserved = cpu_ldx_data(env, addr, sizeof(((secinfo_t *)0)->reserved)); //size is 56
    return reserved;   
}

static
secs_t *cpu_load_secs(CPUX86State *env, secs_t *secs)
{
    target_ulong addr = (target_ulong)secs;
    secs_t *host_secs = cpu_ldx_data(env, addr, sizeof(secs_t));
    return host_secs;
}

static
secs_t *load_secs(secs_t *secs_hostaddr)
{
    uintptr_t addr = (uintptr_t)secs_hostaddr;
    secs_t *host_secs = ldx_raw(addr, sizeof(secs_t));
    return host_secs;
}

#ifdef THREAD_PROTECTION
static
secs_t *cpu_load_tcs(CPUX86State *env, tcs_t *tcs)
{
    target_ulong addr = (target_ulong)tcs;
    tcs_t *host_tcs = cpu_ldx_data(env, addr, sizeof(tcs_t));
    return host_tcs;
}

static
tcs_t *load_tcs(tcs_t *tcs_hostaddr)
{
    uintptr_t addr = (uintptr_t)tcs_hostaddr;
    tcs_t *host_tcs = ldx_raw(addr, sizeof(tcs_t));
    return host_tcs;
}
#endif

static
void *cpu_load_obj(CPUX86State *env, void *host_obj, target_ulong guest_obj, target_ulong size)
{
    void *tmp_host_obj = cpu_ldx_data(env, guest_obj, size);
    memcpy(host_obj, tmp_host_obj, size);
    free(tmp_host_obj);
    return host_obj;
}

static
void cpu_load_n_store(CPUX86State *env, target_ulong dst_guestaddr, target_ulong src_guestaddr, target_ulong size)
{
    void *src_hostaddr = cpu_ldx_data(env, src_guestaddr, size);
    cpu_stx_data(env, dst_guestaddr, src_hostaddr, size);
    free(src_hostaddr); 
}

void helper_mem_execute(CPUX86State *env, target_ulong a0)
{

    int epcm_index = 0;
    uint64_t mem_addr = (uint64_t)a0;
    sgx_dbg(mtrace, "Executing memory (enclave:%d): %p",
            (int)env->cregs.CR_ENCLAVE_MODE, (void *)mem_addr);

    if (env->cregs.CR_ENCLAVE_MODE) {
        sgx_dbg(mtrace, "Executing memory (enclave:%d): %p",
                (int)env->cregs.CR_ENCLAVE_MODE, (void *)mem_addr);
        if (linaddr_is_within_epc(env, mem_addr)){
            epcm_index = epcm_linsearch((void *)mem_addr, env);
#ifdef THREAD_PROTECTION
            sgx_dbg(mtrace, "Access test CR_TCS_PH is %p while TCS in epcm is %p",
                    env->cregs.CR_TCS_PH, epcm[epcm_index].enclave_tcs);
#endif
            
            //if(!is_within_enclave(env, mem_addr)) {
              //  sgx_dbg(trace, "!V: Enclave Executes EPC region not belong to him %lX", mem_addr);
                //raise_exception(env, EXCP0D_GPF);
            //}
            if(env->cregs.CR_ACTIVE_SECS != epcm[epcm_index].enclave_secs){
                sgx_dbg(trace, "!V: EPCM owner property is violated at %p", (void *)mem_addr);
                sgx_dbg(trace, "CR_ACTIVE_SECS is %p while SECS in epcm is %p",
                        env->cregs.CR_ACTIVE_SECS, epcm[epcm_index].enclave_secs);
                //raise_exception(env, EXCP0D_GPF);  
            }
#ifdef THREAD_PROTECTION
            else if(epcm[epcm_index].enclave_tcs != NULL){
                if(env->cregs.CR_TCS_PH != epcm[epcm_index].enclave_tcs){
                    sgx_dbg(trace, "!V: EPCM thread owner property is violated at %p", (void *)mem_addr);
                    sgx_dbg(trace, "CR_TCS_PH is %p while TCS in epcm is %p",
                    env->cregs.CR_TCS_PH, epcm[epcm_index].enclave_tcs);
                    //raise_exception(env, EXCP0D_GPF);  
                }
            }
#endif
            else if((epcm[epcm_index].execute) == 0){
                sgx_dbg(trace, "!V: EPCM execute property is violated at %p", (void *)mem_addr);
                //raise_exception(env, EXCP0D_GPF);
            }
            else if(epcm[epcm_index].page_type != PT_REG){
                sgx_dbg(trace, "!V: EPCM page_type is violated at %p, type:%d",
                        (void *)mem_addr, epcm[epcm_index].page_type);
                //raise_exception(env, EXCP0D_GPF);  
            }
            else if((epcm[epcm_index].pending || epcm[epcm_index].blocked 
                    || epcm[epcm_index].modified) != 0){
                sgx_dbg(trace, "!V: EPCM pending/blocked/modified violated at %p", (void *)mem_addr);
                sgx_dbg(trace,"pending:%d, blocked:%d, modified:%d", epcm[epcm_index].pending, 
                       epcm[epcm_index].blocked, epcm[epcm_index].modified);
                //raise_exception(env, EXCP0D_GPF); 
            }
        }
        else{ //code fetches from inside an enclave to a linear address outside this enclave
            sgx_dbg(trace, "!V: Code fetches from inside an enclave to a linear address at %p", 
                    (void *)mem_addr);
            //raise_exception(env, EXCP0D_GPF);
        }
    }

}

// helper test
void helper_mem_access(CPUX86State *env, target_ulong a0, int operation)
{

    int ld_ = 0;
    int st_ = 1;
    int epcm_index = 0;

    // Do not add overheads prior to any enclave initiation process
    if (!is_enclave_initialized())
        return;

    // FIXME:For EPC access, cpu_ldq_data doesn't seem to work correctly
    uint64_t mem_addr = (uint64_t)a0;

    sgx_dbg(mtrace, "Accessing memory (enclave:%d): %p, is_store:%d",
            (int)env->cregs.CR_ENCLAVE_MODE, (void *)mem_addr, operation);

    // Non-enclave mode access
    //  - no access to EPC pages
    // Enclave mode access
    //  - not allow to access other enclaves
    if (env->cregs.CR_ENCLAVE_MODE) {
        sgx_dbg(mtrace, "Accessing memory (enclave:%d): %p, is_store:%d",
                (int)env->cregs.CR_ENCLAVE_MODE, (void *)mem_addr, operation);
        if (linaddr_is_within_epc(env, mem_addr)){
            epcm_index = epcm_linsearch((void *)mem_addr, env);
#ifdef THREAD_PROTECTION
            sgx_dbg(mtrace, "Access test CR_TCS_PH is %p while TCS in epcm is %p",
                    env->cregs.CR_TCS_PH, epcm[epcm_index].enclave_tcs);
#endif
            //if(!is_within_enclave(env, mem_addr)) {
            //    sgx_dbg(trace, "!V: Enclave Accesses EPC region not belong to him %lX", mem_addr);
                //raise_exception(env, EXCP0D_GPF);
            //}
            if(env->cregs.CR_ACTIVE_SECS != epcm[epcm_index].enclave_secs){
                sgx_dbg(trace, "!V: EPCM owner property is violated at %p", (void *)mem_addr);
                sgx_dbg(trace, "CR_ACTIVE_SECS is %p while SECS in epcm is %p", 
                env->cregs.CR_ACTIVE_SECS, epcm[epcm_index].enclave_secs);
                //raise_exception(env, EXCP0D_GPF);  
            }
#ifdef THREAD_PROTECTION
            else if(epcm[epcm_index].enclave_tcs != NULL){
                if(env->cregs.CR_TCS_PH != epcm[epcm_index].enclave_tcs) {
                    sgx_dbg(trace, "!V: EPCM thread owner property is violated at %p", (void *)mem_addr);
                    sgx_dbg(trace, "CR_TCS_PH is %p while TCS in epcm is %p",
                    env->cregs.CR_TCS_PH, epcm[epcm_index].enclave_tcs);
                    raise_exception(env, EXCP0D_GPF);  
                }
            }
#endif
            else if((operation == ld_) && (epcm[epcm_index].read == 0)){
                sgx_dbg(trace, "!V: EPCM read property is violated at %p", (void *)mem_addr);
                //raise_exception(env, EXCP0D_GPF);  // blocked temporarily just for reaching the end of epcm rwx test
            }
            else if((operation == st_) && (epcm[epcm_index].write == 0)){
                sgx_dbg(trace, "!V: EPCM write property is violated at %p", (void *)mem_addr);
                //raise_exception(env, EXCP0D_GPF);  // blocked temporarily just for reaching the end of epcm rwx test
            }
            else if(epcm[epcm_index].page_type != PT_REG){
                sgx_dbg(trace, "!V: EPCM page_type is violated at %p, type:%d", 
                        (void *)mem_addr, epcm[epcm_index].page_type);
                //raise_exception(env, EXCP0D_GPF);  
            }
            else if((epcm[epcm_index].pending || epcm[epcm_index].blocked 
                    || epcm[epcm_index].modified) != 0){
                sgx_dbg(trace, "!V: EPCM pending/blocked/modified violated at %p", (void *)mem_addr);
                sgx_dbg(trace,"pending:%d, blocked:%d, modified:%d", epcm[epcm_index].pending, 
                       epcm[epcm_index].blocked, epcm[epcm_index].modified);
                //raise_exception(env, EXCP0D_GPF);  
            }
        }
    } 
    else { //Non-enclave mode access

        if ((env->hflags & HF_CPL_MASK == 3) && is_within_user(mem_addr)){
/* 
            //cch: after executing one enclave instance, a certain problem occurs with the below condition
            if(linaddr_is_within_epc(env, mem_addr)){
                sgx_dbg(trace, "!V: User accesses EPC without enclave mode: %lX ", mem_addr);
                //raise_exception(env, EXCP0D_GPF);
            }   
*/
        }

        if (env->hflags & HF_CPL_MASK == 0){
            if(is_within_epc(mem_addr)){
                sgx_dbg(trace, "!V: Kernel accesses EPC: %lX ", mem_addr);
                //raise_exception(env, EXCP0D_GPF);
            }
        }
    }
}

// Get SECS of enclave based on epcm of EPC page
static
secs_t* get_secs_address(epcm_entry_t *cur_epcm)
{
    return (secs_t *)cur_epcm->enclave_secs;
}

#ifdef THREAD_PROTECTION
// Get SECS of enclave based on epcm of EPC page
static
tcs_t* get_tcs_address(epcm_entry_t *cur_epcm)
{
    return (tcs_t *)cur_epcm->enclave_tcs;
}
#endif

// Allocate PKCS padding constant (352 bytes).
static
uint8_t *alloc_pkcs1_5_padding(void) {
    const char first_pkcs1_5_padding[2] = FIRST_PKCS1_5_PADDING;
    const char last_pkcs1_5_padding[20] = LAST_PKCS1_5_PADDING;
    uint8_t *pkcs1_5_padding = (uint8_t *)calloc(sizeof(uint8_t), 352);
    int i;

    // [15:0] = 0100H
    memcpy(pkcs1_5_padding, first_pkcs1_5_padding, 2);

    // [2655:16] = 330 bytes of FFH
    for (i = 0; i < 330; i++) {
        memset(&pkcs1_5_padding[i + 2], 0xFF, sizeof(uint8_t));
    }

    // [2815:2656] = 2004000501020403650148866009060D30313000H
    memcpy(&pkcs1_5_padding[332], last_pkcs1_5_padding, 20);

    return pkcs1_5_padding;
}

// Outputs a 16-byte (128-bit) key
static
void sgx_derivekey(const keydep_t* keydep, unsigned char* outputdata)
{
    unsigned char hash[32];
    unsigned char *input;
    size_t size;

    size = sizeof(keydep_t) + sizeof(process_priv_key);
    input = malloc(size);
    memset(input, 0, size);
    memcpy(input, (unsigned char *)keydep, sizeof(keydep_t));
    memcpy(input + sizeof(keydep_t), (unsigned char *)process_priv_key,
           sizeof(process_priv_key));

    sha256(input, size, hash, 0);

    /* Copy the first 16 bytes (128-bits) */
    memcpy(outputdata, hash, 16);
}

// Performs common parameter (rbx, rcx) checks for EGETKEY
static
void sgx_egetkey_common_check(CPUX86State *env, uint64_t *reg,
                              int alignment, perm_check_t perm)
{
    // If reg is not in CR_ELRANGE, then GP(0)
    if (((uint64_t)reg < env->cregs.CR_ELRANGE[0])
        || ((uint64_t)reg >= env->cregs.CR_ELRANGE[0] + env->cregs.CR_ELRANGE[1])) {
        sgx_dbg(trace, "reg is not in CR_ELRANGE: %lx", (long unsigned int)reg);
        raise_exception(env, EXCP0D_GPF);
    }

    /* If reg is not properly aligned, then GP(0) */
    // FIXME: enforce memory alignment with array declaration inside the enclave.
    // is_aligned((void *)reg, alignment, env);

    /* Check reg is an EPC address */
    uint16_t index_page = epcm_linsearch(reg, env); 

    epcm_entry_t *pepcm = &epcm[index_page];
    assert(pepcm);

    /* Check reg's EPC page is valid */
    epcm_invalid_check(pepcm, env);

    /* Check epcm is blocked */
    epcm_blocked_check(pepcm, env);

    /* check parameter correctness */
    epcm_page_type_check(pepcm, PT_REG, env);

    if (pepcm->enclave_secs != env->cregs.CR_ACTIVE_SECS) {
        sgx_msg(trace, "pepcm->enclave_secs does not match with CR_ACTIVE_SECS");
        raise_exception(env, EXCP0D_GPF);
    }

    epcm_enclave_addr_check(pepcm, ((uint64_t)reg & (~0x0FFFL)), env);
    if (perm.read_check && (pepcm->read != perm.read_perm)) {
        sgx_msg(trace, "Read check failed.");
        raise_exception(env, EXCP0D_GPF);
    }
    if (perm.write_check && (pepcm->write != perm.write_perm)) {
        sgx_msg(trace, "Write check failed.");
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg(trace, "egetkey_common_check finishes well");
}

// ENCLU instruction implemenration.

// EACCEPT instruction.
static
void sgx_eaccept(CPUX86State *env)
{
    secinfo_t *tmp_secinfo;
    secinfo_t *scratch_secinfo; 

    tmp_secinfo = (secinfo_t *)env->regs[R_EBX];
    epc_t *destPage = (epc_t *)env->regs[R_ECX];

    sgx_dbg(trace, "%p, %p\n", (void *)tmp_secinfo, destPage);

    // If RBX is not 64 Byte aligned, then GP(0).
    if (!is_aligned(tmp_secinfo, SECINFO_ALIGN_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_secinfo, SECINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If RBX is not within CR_ELRANGE, then GP(0)
    if (((uint64_t)tmp_secinfo < env->cregs.CR_ELRANGE[0])
            || ((uint64_t)tmp_secinfo >= env->cregs.CR_ELRANGE[0] + env->cregs.CR_ELRANGE[1])) {
            sgx_dbg(trace, "Secinfo is not in CR_ELRANGE: %lx", (long unsigned int)tmp_secinfo);
            raise_exception(env, EXCP0D_GPF);
    }

    // If RBX does not resolve within an EPC, then GP(0).
    check_linaddr_within_epc(tmp_secinfo, env); 

    uint16_t index_secinfo = epcm_linsearch(tmp_secinfo, env); 
    sgx_dbg(trace, "Index of secinfo: %d", index_secinfo);
    epcm_entry_t *epcm_secinfo = &epcm[index_secinfo];

    //NOTE: the last condition is different to SPEC, since it is not reasonable to compare the address of secinfo with the start address of the EPC where secinfo is located
    if ((epcm_secinfo->valid == 0) || (epcm_secinfo->read == 0) ||
        (epcm_secinfo->pending != 0) || (epcm_secinfo->modified != 0) ||
        (epcm_secinfo->blocked != 0) || (epcm_secinfo->page_type != PT_REG) ||
        (epcm_secinfo->enclave_secs != env->cregs.CR_ACTIVE_SECS) ||
            (epcm_secinfo->enclave_addr != ((uint64_t)tmp_secinfo & (~(PAGE_SIZE-1))))) {
        sgx_msg(warn, "there is something wrong in EPCM of secinfo page");
        raise_exception(env, EXCP0D_GPF);
    }

    // scratch_secinfo <- DS:RBX
    scratch_secinfo = cpu_ldx_data(env, tmp_secinfo, sizeof(secinfo_t)); 

    // scratch_secinfo reserved field check. If it is not zero, then GP(0).
    is_reserved_zero(scratch_secinfo->reserved,
                     sizeof(((secinfo_t *)0)->reserved), env);

    // Check if DS:RCX is not 4KByte Aligned
    if (!is_aligned(destPage, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                destPage, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If RCX is not within CR_ELRANGE, then GP(0)
    if (((uint64_t)destPage < env->cregs.CR_ELRANGE[0])
            || ((uint64_t)destPage >= env->cregs.CR_ELRANGE[0] + env->cregs.CR_ELRANGE[1])) {
            sgx_dbg(trace, "DestPage is not in CR_ELRANGE: %lx", (long unsigned int)destPage);
            raise_exception(env, EXCP0D_GPF);
    }

    // If tmp_secs does not resolve within an EPC, then GP(0).
    check_linaddr_within_epc(destPage, env); 

    //TODO: PT_TRIM needs to be added
    if (!(((scratch_secinfo->flags.page_type == PT_REG) && (scratch_secinfo->flags.modified == 0)) ||
        ((scratch_secinfo->flags.page_type == PT_TCS) && (scratch_secinfo->flags.pending == 0) && (scratch_secinfo->flags.modified == 1)) )){
        sgx_msg(warn, "there is something wrong in scratch_secinfo");
        raise_exception(env, EXCP0D_GPF);
    }

    uint16_t index_page = epcm_linsearch(destPage, env); 
    sgx_dbg(trace, "Index of destPage: %d", index_page);
    epcm_entry_t *epcm_dest = &epcm[index_page];

    sgx_dbg(trace, "epcm valid:%d, blocked:%d, page_type:%d, enclave_secs: %x, CR_ACTIVE_SECS: %x", epcm_dest->valid, epcm_dest->blocked, epcm_dest->page_type, epcm_dest->enclave_secs, env->cregs.CR_ACTIVE_SECS);
    // TODO: PT_TRIM needs to be added
    if ((epcm_dest->valid == 0) || (epcm_dest->blocked != 0) ||
            ((epcm_dest->page_type != PT_REG) && (epcm_dest->page_type != PT_TCS)) ||
            (epcm_dest->enclave_secs != env->cregs.CR_ACTIVE_SECS) ){
        sgx_msg(warn, "there is something wrong in destPage");
        raise_exception(env, EXCP0D_GPF);
    }

    // TODO: check the destination EPC page for concurrency

    // Re-check security attributes of the destination EPC page
    if ((epcm_dest->valid == 0) || (epcm_dest->enclave_secs != env->cregs.CR_ACTIVE_SECS)){
        sgx_msg(warn, "there is something wrong in destPage");
        raise_exception(env, EXCP0D_GPF);
    }

    // Verify that accept request matches current EPC page settings
    if((epcm_dest->enclave_addr != (uint64_t)destPage) ||
       (epcm_dest->pending != scratch_secinfo->flags.pending) ||
       (epcm_dest->modified != scratch_secinfo->flags.modified) ||
       (epcm_dest->read != scratch_secinfo->flags.r) ||
       (epcm_dest->write != scratch_secinfo->flags.w) ||
       (epcm_dest->execute != scratch_secinfo->flags.x) ||
       (epcm_dest->page_type != scratch_secinfo->flags.page_type)){
        sgx_msg(warn, "accept request does not match current EPC page settings");
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_PAGE_ATTRIBUTES_MISMATCH;
        goto Done;
    }

    // TODO: Check that all required threads have left enclave

    // Get pointer to the SECS to which the EPC page belongs
    secs_t *tmp_secs =  get_secs_address(epcm_dest);
    secs_t *tmp_secs_host = load_secs(tmp_secs); 
    // For TCS pages, perform additional checks. a new TCS page can allocated by EAUG + EMODT
    if (scratch_secinfo->flags.page_type == PT_TCS){
        tcs_t *tcs = (tcs_t *)destPage;
        tcs_t *tcs_host = (tcs_t *)cpu_ldx_data(env, tcs, sizeof(tcs_t)); 
        checkReservedBits((uint64_t *)&(tcs_host->flags), 0xFFFFFFFFFFFFFFFEL, env);

        // Checking that TCS.FLAGS.DBGOPTIN, TCS stack, and TCS status are correctly initialized
        // Note: even though the below checking codes are located outside this if statement in spec, I think this is correct.
        if( (tcs_host->flags.dbgoptin != 0) || (tcs_host->cssa >= tcs_host->nssa) ){ //TODO?: no aep and state field in TCS, but spec checks it.
            sgx_msg(warn, "TCS is not correctly initialized");
            raise_exception(env, EXCP0D_GPF);
        }

        // Check consistency of FS & GS Limit
        if ((tmp_secs_host->attributes.mode64bit == 0)
            && (((tcs_host->fslimit & 0x0FFF) != 0x0FFF)
            || ((tcs_host->gslimit & 0x0FFF) != 0x0FFF))) {
            raise_exception(env, EXCP0D_GPF);
        }
        free(tcs_host);
    }

    // Clear PENDING/MODIFIED flags to mark accept operation complete
    epcm_dest->pending = 0;
    epcm_dest->modified = 0;

    // Clear EAX and ZF to indicate successful completion
    env->eflags &= ~CC_Z;
    env->regs[R_EAX] = 0;

Done:
    // clear flags : CF, PF, AF, OF, SF
    env->eflags &= ~(CC_C | CC_P | CC_A | CC_S | CC_O);

    env->cregs.CR_CURR_EIP = env->cregs.CR_NEXT_EIP;
    env->cregs.CR_ENC_INSN_RET = true;
#if PERF
    int64_t eid;
    eid = tmp_secs_host->eid_reserved.eid_pad.eid;
    qenclaves[eid].stat.eaccept_n++;
    qenclaves[eid].stat.enclu_n++;
#endif
    free(tmp_secs_host);
    free(scratch_secinfo);
    sgx_dbg(trace, "eaccept finishes well");
}

// EACCEPTCOPY instruction
static
void sgx_eacceptcopy(CPUX86State *env)
{
    //RBX: Secinfo addr(In, EA)
    //RCX: Destination EPC addr(In, EA)
    //RDX: Source EPC addr(In, EA)
    //EAX: Error code(Out)

    uint64_t sec_index = 0 , dst_index = 0, src_index = 0;
    secinfo_t *tmp_secinfo;
    secinfo_t *scratch_secinfo;
    epc_t *destPage;
    epc_t *srcPage;

    tmp_secinfo = (secinfo_t *)env->regs[R_EBX];
    destPage = (epc_t *)env->regs[R_ECX];
    srcPage  = (epc_t *)env->regs[R_EDX];

    sgx_dbg(trace, "eacceptcopy called: %p, %p, %p", (void *)tmp_secinfo, destPage, srcPage);

    if(!is_aligned(tmp_secinfo, SECINFO_ALIGN_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes", tmp_secinfo, SECINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    if(!is_aligned(destPage, PAGE_SIZE) || !is_aligned(srcPage, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment on destPage or srcPage" );
        raise_exception(env, EXCP0D_GPF);
    }

    if (((uint64_t) tmp_secinfo < env->cregs.CR_ELRANGE[0])
            || ((uint64_t) tmp_secinfo >= (env->cregs.CR_ELRANGE[0] + env->cregs.CR_ELRANGE[1]))) {
            sgx_dbg(trace, "Secinfo is not in CR_ELRANGE: %lx", (long unsigned int) tmp_secinfo);
            raise_exception(env, EXCP0D_GPF);
    }

    if (((uint64_t) destPage < env->cregs.CR_ELRANGE[0])
            || ((uint64_t) destPage >= (env->cregs.CR_ELRANGE[0] + env->cregs.CR_ELRANGE[1]))) {
            sgx_dbg(trace, "Dst EPC page is not in CR_ELRANGE: %lx", (long unsigned int)destPage);
            raise_exception(env, EXCP0D_GPF);
    }

    if (((uint64_t) srcPage < env->cregs.CR_ELRANGE[0])
            || ((uint64_t) srcPage >= (env->cregs.CR_ELRANGE[0] + env->cregs.CR_ELRANGE[1]))) {
            sgx_dbg(trace, "Src EPC page is not in CR_ELRANGE: %lx", (long unsigned int)srcPage);
            raise_exception(env, EXCP0D_GPF);
    }

    //XXX: isn't it redundant ?
    check_linaddr_within_epc((void *)tmp_secinfo, env);
    check_linaddr_within_epc((void *)destPage, env);
    check_linaddr_within_epc((void *)srcPage, env);

    sec_index = epcm_linsearch((void *)tmp_secinfo, env);
    sgx_dbg(trace, "debug index of secinfo: %d", sec_index);

    epcm_entry_t *epcm_secinfo = &epcm[sec_index];

    if(epcm_secinfo->valid == 0 || epcm_secinfo->read == 0 || epcm_secinfo->pending != 0 ||
       epcm_secinfo->modified != 0 || epcm_secinfo->blocked != 0 || epcm_secinfo->page_type != PT_REG ||
       // epcm_secinfo->enclave_secs != env->cregs.CR_ACTIVE_SECS || epcm_secinfo->enclave_addr != (uint64_t) tmp_secinfo) {
       // knh : below condition is different from SGX document.
       //       I think above condition is right. 
       epcm_secinfo->enclave_secs != env->cregs.CR_ACTIVE_SECS || epcm_secinfo->enclave_addr == (uint64_t) tmp_secinfo) {
        sgx_msg( warn, "there is something wrong in EPCM of secinfo page");
        raise_exception(env, EXCP0D_GPF);
    }

    //memset(&scratch_secinfo, 0, sizeof(secinfo_t));
    scratch_secinfo = cpu_ldx_data( env, tmp_secinfo, sizeof(secinfo_t));

    //check for mis-configured secinfo flags
    is_reserved_zero(scratch_secinfo->reserved, sizeof(((secinfo_t *)0)->reserved), env);
    if((scratch_secinfo->flags.r == 0 && scratch_secinfo->flags.w != 0) ||
       scratch_secinfo->flags.page_type != PT_REG) {
        sgx_msg( warn, "there is something wrong in secinfo flags");
        raise_exception(env, EXCP0D_GPF);
    }

    //check security attributes of the source EPC page
    src_index = epcm_linsearch((void*)srcPage, env);
    sgx_dbg(trace, "debug index of srcPage: %d", src_index);

    epcm_entry_t *epcm_srcPage = &epcm[src_index];

    if(epcm_srcPage->valid == 0 || epcm_srcPage->pending != 0 || epcm_srcPage->modified != 0 ||
       // epcm_srcPage->blocked != 0 || epcm_srcPage->page_type != PT_REG ||
       // knh : Above condition is wrong.
       //       I think that SGX spec has a mistake. 
       //       page_type have to be PT_TCS.
       //       so I changed like following. 
       epcm_srcPage->blocked != 0 || epcm_srcPage->page_type != PT_TCS ||
       // epcm_srcPage->enclave_secs != env->cregs.CR_ACTIVE_SECS || epcm_srcPage->enclave_addr != (uint64_t)srcPage) {
       // knh : below condition is not enough condition, 
       //       it is different from SGX document.
       //       I think above annotated condition is right. 
       epcm_srcPage->enclave_secs != env->cregs.CR_ACTIVE_SECS ) {
        sgx_msg( warn, "there is something wrong in EPCM of source page");
        raise_exception(env, EXCP0D_GPF);
    }

    //check security attributes of the destination EPC page
    dst_index = epcm_linsearch((void*)destPage, env);
    sgx_dbg(trace, "debug index of destPage: %d", dst_index);

    epcm_entry_t *epcm_destPage = &epcm[dst_index];

    if(epcm_destPage->valid == 0 || epcm_destPage->pending != 1 || epcm_destPage->modified != 0 ||
      epcm_destPage->page_type != PT_REG || epcm_destPage->enclave_secs != env->cregs.CR_ACTIVE_SECS) {
        sgx_msg( warn, "there is something wrong in EPCM of destination page");
        env->eflags = 1;
        env->regs[R_EAX] = ERR_SGX_PAGE_ATTRIBUTES_MISMATCH;
        goto Done;
    }
    //TODO: check destination EPC page for concurrency 

    //Re-check security attributes of the destination EPC page
    //check security attributes of the destination EPC page
    if(epcm_destPage->valid == 0 || epcm_destPage->pending != 1 || epcm_destPage->modified != 0 ||
      epcm_destPage->read != 1 || epcm_destPage->write != 1 || epcm_destPage->execute != 0 ||
      epcm_destPage->page_type != scratch_secinfo->flags.page_type ||
      // epcm_destPage->enclave_secs != env->cregs.CR_ACTIVE_SECS || epcm_destPage->enclave_addr != destPage ) {
      // knh : below condition is different from SGX document.
      //       I think above annotated condition is right. 
      // epcm_destPage->enclave_secs != env->cregs.CR_ACTIVE_SECS || epcm_destPage->enclave_addr == destPage ) {
      //       but I omitted the condition for the test
      epcm_destPage->enclave_secs != env->cregs.CR_ACTIVE_SECS ) {
        sgx_msg( warn, "there is something wrong in EPCM attributes of destination page");
        sgx_dbg(trace, "%d, %d, %d, %d, %d, %d, %d, %d",
            epcm_destPage->valid, epcm_destPage->pending, epcm_destPage->modified, 
            epcm_destPage->read, epcm_destPage->write, epcm_destPage->execute,
            epcm_destPage->page_type != scratch_secinfo->flags.page_type,
            epcm_destPage->enclave_secs != env->cregs.CR_ACTIVE_SECS 
        );
        raise_exception(env, EXCP0D_GPF);
    }

    //copy 4KBytes from the source to destination EPC page
    cpu_load_n_store(env, destPage, srcPage, PAGE_SIZE); 
#ifdef THREAD_PROTECTION
    epcm_destPage->enclave_tcs = epcm_srcPage->enclave_tcs;
#endif

    //update epcm permission
    epcm_destPage->read    |= scratch_secinfo->flags.r;
    epcm_destPage->write   |= scratch_secinfo->flags.w;
    epcm_destPage->execute |= scratch_secinfo->flags.x;
    epcm_destPage->pending  = 0;

    env->eflags &= ~(CC_Z);
    env->regs[R_EAX] = 0;

    Done:
        env->eflags &= ~(CC_C | CC_P | CC_A | CC_O | CC_S);

    cpu_stx_data( env, tmp_secinfo, scratch_secinfo, sizeof(secinfo_t));
    sgx_dbg( trace, "after cpu_stx_data");

    free(scratch_secinfo);

    // next instruction
    env->cregs.CR_CURR_EIP = env->cregs.CR_NEXT_EIP;
    env->cregs.CR_ENC_INSN_RET = true;

    sgx_dbg(trace, "eacceptcopy finishes well");
}

// EENTER instruction
static
void sgx_eenter(CPUX86State *env)
{
    // RBX: TCS(In, EA)
    // RCX: AEP(In, EA)
    // RAX: Error(Out, ErrorCode)
    // RCX: Address_IP_Following_EENTER(Out, EA)

    bool tmp_mode64;
    uint64_t tmp_fsbase;
    uint64_t tmp_fslimit;
    uint64_t tmp_gsbase;
    uint64_t tmp_gslimit;
    uint64_t tmp_ssa;
    uint64_t tmp_xsize;
    uint64_t tmp_gpr;
    uint64_t tmp_target;
    uint64_t eid;
    uint16_t index_gpr;
    uint16_t index_tcs;
    // Unused variables.
    // uint16_t iter;
    // uint16_t index_secs;
    // uint64_t tmp_ssa_page;

    // XXX. uint64_t* -> void*
    tcs_t *tcs = (tcs_t *)env->regs[R_EBX];
    uint64_t *aep = (uint64_t *)env->regs[R_ECX];
    tcs_t tmp_tcs;  
    cpu_load_obj(env, &tmp_tcs, tcs, sizeof(tcs_t));  

    index_tcs = epcm_linsearch(tcs, env); 
    tmp_mode64 = (env->efer & MSR_EFER_LMA) && (env->segs[R_CS].flags & DESC_L_MASK);

    sgx_dbg(eenter, "aep: %p, tcs: %p", aep, tcs);
    sgx_dbg(eenter, "index_tcs: %d, mode64: %d", index_tcs, tmp_mode64);

    // Also Need to check DS[S] == 1 and DS[11] and DS[10]
    if ((!tmp_mode64) && ((&env->segs[R_DS] != NULL) ||
        ((!extractBitVal(env->segs[R_DS].selector, 11)) &&
        (extractBitVal(env->segs[R_DS].selector, 10)) &&
        (env->segs[R_DS].flags & DESC_S_MASK)))) {
        sgx_msg(warn, "check DS failed.");
        raise_exception(env, EXCP0D_GPF);
    }

    // Check that CS, SS, DS, ES.base is 0
    if (!tmp_mode64) {
        if (((&env->segs[R_CS] != NULL) && (env->segs[R_CS].base != 0)) ||
            (env->segs[R_DS].base != 0)) {
            sgx_msg(warn, "check CS, DS failed.");
            raise_exception(env, EXCP0D_GPF);
        }
    }

    if ((&env->segs[R_ES] != NULL) && (env->segs[R_ES].base != 0)) {
        sgx_msg(warn, "check ES failed.");
        raise_exception(env, EXCP0D_GPF);
    }
    if ((&env->segs[R_SS] != NULL) && (env->segs[R_SS].base != 0)) {
        sgx_msg(warn, "check SS failed.");
        raise_exception(env, EXCP0D_GPF);
    }
    if ((&env->segs[R_SS] != NULL) &&
        ((env->segs[R_SS].flags & DESC_B_MASK) == 0)) {
        sgx_msg(warn, "check SS flag failed.");
        raise_exception(env, EXCP0D_GPF);
    }

    // Check if DS:RBX is not 4KByte Aligned
    if (!is_aligned(tcs, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tcs, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    // Temporarily block
    check_linaddr_within_epc(tcs, env);

    // Check if AEP is canonical
    if (tmp_mode64) {
        is_canonical((uint64_t)aep, env); //cch: TODO - free is_canonical contents
    }
    // TODO - Check concurrency of operations on TCS
#if DEBUG
    sgx_dbg(trace, "TCS-> nssa = %d", tmp_tcs.nssa);
    sgx_dbg(trace, "TCS-> cssa = %d", tmp_tcs.cssa);
    sgx_dbg(trace, "Index_TCS  valid : %d Blocked : %d",
                    epcm[index_tcs].valid,
                    epcm[index_tcs].blocked );
    sgx_dbg(trace, "EPCM[index_tcs] %"PRIx64" tcs %"PRIx64" page_type %d",
                    epcm[index_tcs].enclave_addr,
                    (uint64_t)tcs,
                    epcm[index_tcs].page_type);
#endif
    // Check Validity and whether access has been blocked
    epcm_invalid_check(&epcm[index_tcs], env);
    epcm_blocked_check(&epcm[index_tcs], env);

    // Async Exit pointer -- make a struct of registers
    // Check for Address and page type
    epcm_enclave_addr_check(&epcm[index_tcs], (uint64_t)tcs, env);
    epcm_page_type_check(&epcm[index_tcs], PT_TCS, env);

    // Alignment OFSBASGX with Page Size
    if (!is_aligned((void *)tmp_tcs.ofsbasgx, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                (void *)tmp_tcs.ofsbasgx, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    if (!is_aligned((void *)tmp_tcs.ogsbasgx, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                (void *)tmp_tcs.ogsbasgx, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    // Get the address of SECS for TCS - Implicit Access - Cached by the processor - EPC
    // Obtain the Base and Limits of FS and GS Sections
    // Check proposed FS/GS segments fall within DS
    secs_t *secs =  get_secs_address(&epcm[index_tcs]); // TODO: Change when the ENCLS is implemented - pageinfo_t   
    secs_t *tmp_secs = load_secs(secs); // cch: tmp_secs needs to be freed later

    // Alignment - OSSA With Page Size
    if (!is_aligned((void *)(tmp_secs->baseAddr + tmp_tcs.ossa), PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                (void *)(tmp_secs->baseAddr + tmp_tcs.ossa), PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    if (!tmp_mode64) {
        tmp_fsbase = tmp_tcs.ofsbasgx + tmp_secs->baseAddr;
        tmp_fslimit = tmp_fsbase + tmp_secs->baseAddr + tmp_tcs.fslimit;
        tmp_gsbase = tmp_tcs.ogsbasgx + tmp_secs->baseAddr;
        tmp_gslimit = tmp_gsbase + tmp_secs->baseAddr + tmp_tcs.gslimit;
        // if FS wrap-around, make sure DS has no holes
        if (tmp_fslimit < tmp_fsbase) {
            if (env->segs[R_DS].limit < DSLIMIT) {
                sgx_msg(warn, "Invalid FS range.");
                raise_exception(env, EXCP0D_GPF);
            } else {
                if (tmp_fslimit > env->segs[R_DS].limit) {
                   sgx_msg(warn, "Invalid FS range.");
                   raise_exception(env, EXCP0D_GPF);
                }
            }
        }
        // if GS wrap-around, make sure DS has no holes
        if (tmp_gslimit < tmp_gsbase) {
            if (env->segs[R_DS].limit < DSLIMIT) {
                sgx_msg(warn, "Invalid DS range.");
                raise_exception(env, EXCP0D_GPF);
            } else {
                if (tmp_gslimit > env->segs[R_DS].limit) {
                    sgx_msg(warn, "Invalid DS range.");
                    raise_exception(env, EXCP0D_GPF);
                }
            }
        }
    } else {
        tmp_fsbase = tmp_tcs.ofsbasgx + tmp_secs->baseAddr;
        tmp_gsbase = tmp_tcs.ogsbasgx + tmp_secs->baseAddr;

        is_canonical((uint64_t)(void*)tmp_fsbase, env);
        is_canonical((uint64_t)(void*)tmp_gsbase, env);
    }

    // Ensure that the FLAGS field in the TCS does not have any reserved bits set
    checkReservedBits((uint64_t *)&tmp_tcs.flags, 0xFFFFFFFFFFFFFFFEL, env);
    eid = tmp_secs->eid_reserved.eid_pad.eid;

    // SECS must exist and enclave must have previously been EINITted
    if ((tmp_secs == NULL) && !checkEINIT(eid)) { // != NULL taken care of earlier itself
        sgx_msg(warn, "Check secs failed.");
        raise_exception(env, EXCP0D_GPF);
    }
#if DEBUG
    sgx_dbg(trace, "SECS and checkEINIT worked %d %d", tmp_secs->attributes.mode64bit, tmp_mode64);
#endif
    // Make sure the logical processor’s operating mode matches the enclave
    if (tmp_secs->attributes.mode64bit != tmp_mode64) {
        sgx_msg(warn, "Attribute mode64bit mismatched.");
        raise_exception(env, EXCP0D_GPF);
    }
    // OSFXSR == 0 ?
    if (!(env->cr[4] & CR4_OSFXSR_MASK)) {
        sgx_msg(warn, "OSFXSR check failed.");
        raise_exception(env, EXCP0D_GPF);
    }

    // Check for legal values of SECS.ATTRIBUTES.XFRM
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        if (tmp_secs->attributes.xfrm != 0x03) {
        sgx_msg(warn, "Attribute mode64bit mismatched.");
            raise_exception(env, EXCP0D_GPF);
        } else
             if ((tmp_secs->attributes.xfrm & env->xcr0) ==
                 tmp_secs->attributes.xfrm) {
                 sgx_msg(warn, "secs.attributes.xfrm mismatch");
                 raise_exception(env, EXCP0D_GPF);
        }
    }

    // Make sure the SSA contains at least one more frame
    // Causing Exception
    if (tmp_tcs.cssa >= tmp_tcs.nssa) {
        raise_exception(env, EXCP0D_GPF);
    }

#if DEBUG
    sgx_dbg(trace, "SSA ossa: %lx nssa %lx cssa %d",
            (long unsigned int)tmp_tcs.ossa, (long unsigned int)tmp_tcs.nssa, (long unsigned int)tmp_tcs.cssa);
#endif

    // Compute linear address of SSA frame
    tmp_ssa = tmp_tcs.ossa + tmp_secs->baseAddr + PAGE_SIZE * tmp_secs->ssaFrameSize * (tmp_tcs.cssa);
    tmp_xsize = compute_xsave_frame_size(env, tmp_secs->attributes);

    sgx_dbg(trace, "ssa: %p (size:%lu) base: %p",
            (void *)tmp_ssa, tmp_xsize, (void *)tmp_secs->baseAddr);

// TODO: Implement XSAVE/XSTOR related spec

    // Compute Address of GPR Area
    tmp_gpr = tmp_ssa + PAGE_SIZE * (tmp_secs->ssaFrameSize) - sizeof(gprsgx_t);
    index_gpr = epcm_linsearch((void *)tmp_gpr, env);  

    // Temporarily block
    check_linaddr_within_epc((void *)tmp_gpr, env); 
    // Check for validity and block
    epcm_invalid_check(&epcm[index_gpr], env);
    epcm_blocked_check(&epcm[index_gpr], env);
    // XXX: Spec might be wrong in r2 p.77:
    // the check EPCM(DS:TMP_GPR).ENCLAVEADDRESS != DS:TMP_GPR)
    // ENCLAVEADDRESS is assumed to be the epc page address, whreas
    // TMP_GPR address is within the page.
    // In second parameter, use tmp_ssa instead of tmp_gpr for now.
    epcm_field_check(&epcm[index_gpr], (uint64_t)tmp_ssa, PT_REG,
                     (uint64_t)epcm[index_tcs].enclave_secs, env);
    if (!epcm[index_gpr].read || !epcm[index_gpr].write) {
        raise_exception(env, EXCP0D_GPF);
    }
    if (!tmp_mode64) {
        checkWithinDSSegment(env, tmp_gpr + sizeof(env->regs[R_EAX]));
    }

    // GetPhysical Address of TMP_GPR
    env->cregs.CR_GPR_PA = tmp_gpr;

#if DEBUG
    sgx_dbg(trace, "Physical Address obtained cr_gpr_a: %lp", (void *)env->cregs.CR_GPR_PA);
#endif
    tmp_target = env->eip;

    if (tmp_mode64) {
        is_canonical(tmp_target, env);
    } else {
        if (tmp_target > env->segs[R_CS].limit) {
            raise_exception(env, EXCP0D_GPF);
        }
    }
    // Ensure the enclave is not already active and also concurrency of TCS
    /* if ( tcs->state == ACTIVE )
           raise_exception(env, EXCP0D_GPF);
    */
    curr_Eid = tmp_secs->eid_reserved.eid_pad.eid;
    env->cregs.CR_ENCLAVE_MODE = true;  
    env->cregs.CR_ACTIVE_SECS = secs; 
    env->cregs.CR_ELRANGE[0] = tmp_secs->baseAddr;
    env->cregs.CR_ELRANGE[1] = tmp_secs->size;

    sgx_dbg(trace, "range: %p-%lx",
            (void *)env->cregs.CR_ELRANGE[0],
            env->cregs.CR_ELRANGE[1]);
    // Save state for possible AEXs

    env->cregs.CR_TCS_LA = (uint64_t)tcs;
    env->cregs.CR_TCS_PH = return_hostaddr(env, (uint64_t)tcs);
    sgx_dbg(trace, "CR_TCS_LA: %p, CR_TCS_PH: %p", env->cregs.CR_TCS_LA, env->cregs.CR_TCS_PH); 
    env->cregs.CR_AEP = (uint64_t)aep;
    sgx_dbg(trace, "CR_AEP: %p", env->cregs.CR_AEP); 

    // Save the hidden portions of FS and GS
    env->cregs.CR_SAVE_FS.selector = env->segs[R_FS].selector;
    env->cregs.CR_SAVE_FS.base = env->segs[R_FS].base;
    env->cregs.CR_SAVE_FS.limit = env->segs[R_FS].limit;
    env->cregs.CR_SAVE_FS.flags = env->segs[R_FS].flags;

    env->cregs.CR_SAVE_GS.selector = env->segs[R_GS].selector;
    env->cregs.CR_SAVE_GS.base = env->segs[R_GS].base;
    env->cregs.CR_SAVE_GS.limit = env->segs[R_GS].limit;
    env->cregs.CR_SAVE_GS.flags = env->segs[R_GS].flags;

    // If XSAVE is enabled, save XCR0 and replace it with SECS.ATTRIBUTES.XFRM
    if ((env->cr[4] & CR4_OSXSAVE_MASK)) {
        env->cregs.CR_SAVE_XCR0 = env->xcr0;
        env->xcr0 = tmp_secs->attributes.xfrm;
    }

    // Set eip into the enclave
    env->eip = tmp_secs->baseAddr + tmp_tcs.oentry;
    // Following used to affect the tb flow
    env->cregs.CR_CURR_EIP = env->eip;
    sgx_dbg(trace, "entry ptr: %p (base: %p, offset: %lx)",
            (void *)env->eip, (void *)tmp_secs->baseAddr, tmp_tcs.oentry);

    // Return values
    env->regs[R_EAX] = tmp_tcs.cssa;
    env->regs[R_ECX] = env->cregs.CR_NEXT_EIP;

#ifdef TEST
    void (*func)(void);
    func = (typeof(func))*((uint64_t *)(env->regs[R_ECX]));
//    uint64_t funcPtr = (uint64_t)func;
#endif

#if DEBUG
{
    int i;
    fprintf(stderr, "%p :", env->eip);
    for (i = 0; i < 20; i ++) {
        fprintf(stderr, "%02X ", cpu_ldub_data(env, env->eip + i));
    }
    fprintf(stderr, "\n");
}
#endif

    // Save the outside RSP and RBP so they can be restored on interrupt or EEXIT
    gprsgx_t *tmp_gpr_host; 
    tmp_gpr = (gprsgx_t *)env->cregs.CR_GPR_PA; 
    tmp_gpr_host = cpu_ldx_data(env, tmp_gpr, sizeof(gprsgx_t)); //cch: tmp_gpr should be copied to original gpr and then freed later
    tmp_gpr_host->ursp = env->regs[R_ESP];
    tmp_gpr_host->urbp = env->regs[R_EBP];

    sgx_dbg(info, "ursp(old esp): %p   urbp(old ebp) %p at eenter",
            (void *)tmp_gpr_host->ursp,
            (void *)tmp_gpr_host->urbp);

    sgx_dbg(trace, "transfer to rip: %p (rsp: %p, rbp: %p)",
            (void *)env->eip,
            (void *)env->regs[R_ESP],
            (void *)env->regs[R_EBP]);

    // Swap FS/GS (XXX?)
    env->segs[R_FS].base = tmp_fsbase;
    env->segs[R_FS].limit = tmp_tcs.fslimit;

    env->segs[R_FS].flags |= 0x01;
    env->segs[R_FS].flags |= env->segs[R_DS].flags & DESC_W_MASK;
    env->segs[R_FS].flags |= DESC_S_MASK;
    env->segs[R_FS].flags |= env->segs[R_DS].flags & DESC_DPL_MASK;
    env->segs[R_FS].flags |= DESC_G_MASK;
    env->segs[R_FS].flags |= DESC_B_MASK;
    env->segs[R_FS].flags |= DESC_P_MASK;
    env->segs[R_FS].flags |= env->segs[R_DS].flags & DESC_AVL_MASK;
    env->segs[R_FS].flags |= env->segs[R_DS].flags & DESC_L_MASK;
    env->segs[R_FS].selector = 0x0B;

    env->segs[R_GS].base = tmp_gsbase;
    env->segs[R_GS].limit = tmp_tcs.gslimit;

    env->segs[R_GS].flags |= 0x01;
    env->segs[R_GS].flags |= env->segs[R_DS].flags & DESC_W_MASK;
    env->segs[R_GS].flags |= DESC_S_MASK;
    env->segs[R_GS].flags |= env->segs[R_DS].flags & DESC_DPL_MASK;
    env->segs[R_GS].flags |= DESC_G_MASK;
    env->segs[R_GS].flags |= DESC_B_MASK;
    env->segs[R_GS].flags |= DESC_P_MASK;
    env->segs[R_GS].flags |= env->segs[R_DS].flags & DESC_AVL_MASK;
    env->segs[R_GS].flags |= env->segs[R_DS].flags & DESC_L_MASK;
    env->segs[R_GS].selector = 0x0B;


    // For later EEXIT
    env->cregs.CR_EXIT_EIP = env->cregs.CR_NEXT_EIP;
    sgx_dbg(info,"saved EXIT_EIP at eenter: %lX", env->cregs.CR_EXIT_EIP);

    //update_ssa_base();

    sgx_dbg(trace, "async rip: %p", (void *)env->cregs.CR_AEP);

#if DEBUG
    env->cregs.CR_DBGOPTIN = tmp_tcs.flags.dbgoptin;
#endif

    /* Supress all code breakpoints -- Not Needed as of now */
    /*
    if ( !env->cregs.CR_DBGOPTIN) {
        env->cregs.CR_SAVE_TF = env->eflags & HF_TF_MASK;
        env->eflags = env->eflags & ~(HF_TF_MASK);
        // Support Monitor Trap Flag
        // Clear All pending debug exceptions
        // Clear pending MTF VM EXIT
    }
    else {
        if (env->eflags & HF_TF_MASK) {
        }
        if ( vmcs.mtf) {
        }
    } */

    // Added for QEMU TB flow while operating in enclave mode
    env->cregs.CR_ENC_INSN_RET = true;

    CPUState *cs = CPU(x86_env_get_cpu(env));
    tlb_flush(cs, 1);

#if PERF
    qenclaves[eid].stat.mode_switch++;
    qenclaves[eid].stat.tlbflush_n++;
    qenclaves[eid].stat.eenter_n++;
    qenclaves[eid].stat.enclu_n++;
#endif
    cpu_stx_data(env, tmp_gpr, tmp_gpr_host, sizeof(gprsgx_t));
    free(tmp_gpr_host);
    free(tmp_secs);
    sgx_dbg(trace, "eenter finishes well");
    return;
}

// EEXIT instruction
static
void sgx_eexit(CPUX86State *env)
{
    // RBX: Target_Address(In, EA)
    // RCX: Current_AEP(In, EA)
    bool tmp_mode64;
    uint64_t retAddr;
    secs_t *secs;
    void *addr;
    gprsgx_t *tmp_gpr;
    tcs_t *tcs;
    secs_t *tmp_secs_host; 
    gprsgx_t *tmp_gpr_host; 
    tcs_t *tmp_tcs_host; 

    sgx_dbg(trace, "Current ESP: %p   EBP: %p", (void *)env->regs[R_ESP], (void *)env->regs[R_EBP]);
    sgx_dbg(trace, "CR_ACTIVE_SECS: %p", (void *)env->cregs.CR_ACTIVE_SECS); 

    secs = (secs_t*)env->cregs.CR_ACTIVE_SECS;

    // FIXME: Currently not used
    retAddr = env->regs[R_EBX];
    if(retAddr != 0) {
        sgx_dbg(trace, "EEXIT will return to provided addr: %lx", retAddr);
    } else {
        sgx_dbg(trace, "EEXIT will return saved EXIT_EIP: %lx", env->cregs.CR_EXIT_EIP);
    }
    addr = (void *)env->regs[R_EBX];
    tmp_mode64 = (env->efer & MSR_EFER_LMA) && (env->segs[R_CS].flags & DESC_L_MASK);

    if (tmp_mode64) {
        is_canonical((uint64_t)addr, env);
    } else {
        if ((uint64_t)addr > env->segs[R_CS].limit) {
            raise_exception(env, EXCP0D_GPF);
        }
    }

    // TODO: will fix it to save current CR_EXIT_EIP and
    // address right after eexit that should be returned
    // after ERESUME.

    // For trampoline
    if(retAddr != 0) {
        //is it necessary ? may be not
        env->eip = retAddr;
        // get tcs
        tcs = (tcs_t *)env->cregs.CR_TCS_LA;
        tmp_tcs_host = cpu_ldx_data(env, tcs, sizeof(tcs_t)); //cch: should be freed later. should be copied to original
        {
            sgx_dbg(trace, "SSA ossa: %lX nssa %d cssa %d",
                    tmp_tcs_host->ossa, tmp_tcs_host->nssa, tmp_tcs_host->cssa);
        }

        // Get current GPR
        tmp_gpr = (gprsgx_t *)env->cregs.CR_GPR_PA;
        //sgx_dbg(trace, "current gpr is %lp\t ssa is %lp", tmp_gpr,tmp_ssa);
        tmp_gpr_host = cpu_ldx_data(env, tmp_gpr, sizeof(gprsgx_t)); //cch: should be copied to original. should be freed later

        saveState(tmp_gpr_host, env);
	    // Push old CR_EXIT_EIP to the SSA
        tmp_gpr_host->SAVED_EXIT_EIP = env->cregs.CR_EXIT_EIP;
        // Push Next eip to the SSA
        tmp_gpr_host->rip = env->cregs.CR_NEXT_EIP;
        sgx_dbg(trace, "Addr followed by eexit is %lX", env->cregs.CR_NEXT_EIP);

        // Increase cssa by one
        tmp_tcs_host->cssa += 1;

        // Change CR_EXIT_EIP to designated addr
        env->cregs.CR_EXIT_EIP = retAddr;

        // ESP should be changed to point a non-enclave sp.
        // Currently, we don't have a speical stack memory area for trampoline
        // So we subtract sufficient number from the ursp to make it not to overwrite
        // user stack area reserved before calling eenter.
        // XXX: it works fine now, but it could crush if the function calling eenter
        // has huge local variable in it.
        env->regs[R_ESP] = tmp_gpr_host->ursp - 0x1000;
        env->regs[R_EBP] = 0;
    
        cpu_stx_data(env, tcs, tmp_tcs_host, sizeof(tcs_t)); 
        free(tmp_tcs_host); 
    }
    else {
        sgx_dbg(trace, "Entry of else. tmp_gpr will be loaded");
        tmp_gpr = (gprsgx_t *)env->cregs.CR_GPR_PA; 
        tmp_gpr_host = cpu_ldx_data(env, tmp_gpr, sizeof(gprsgx_t)); //cch: tmp_gpr_host don't have to be copied to original, but should be freed later
        // Change the stack pointer as untrusted area
        env->regs[R_ESP] = tmp_gpr_host->ursp;
        env->regs[R_EBP] = tmp_gpr_host->urbp;
        sgx_dbg(trace, "restored ESP: %p   EBP: %p", (void *)env->regs[R_ESP], (void *)env->regs[R_EBP]);
    }

    // Return Current AEP in RCX
    env->regs[R_EBX] = env->cregs.CR_TCS_LA; //cch: added for multi-threading (not in the SPEC)
    sgx_dbg(trace, "CR_TCS_LA in eexit %p", env->cregs.CR_TCS_LA);
    env->regs[R_ECX] = env->cregs.CR_AEP;

    env->segs[R_FS].selector = env->cregs.CR_SAVE_FS.selector;
    env->segs[R_FS].base = env->cregs.CR_SAVE_FS.base;
    env->segs[R_FS].limit = env->cregs.CR_SAVE_FS.limit;
    env->segs[R_FS].flags = env->cregs.CR_SAVE_FS.flags;
    env->segs[R_GS].selector = env->cregs.CR_SAVE_GS.selector;
    env->segs[R_GS].base = env->cregs.CR_SAVE_GS.base;
    env->segs[R_GS].limit = env->cregs.CR_SAVE_GS.limit;
    env->segs[R_GS].flags = env->cregs.CR_SAVE_GS.flags;
    // Restore XCR0 if needed
    if ((env->cr[4] & CR4_OSXSAVE_MASK)) {
        env->xcr0 = env->cregs.CR_SAVE_XCR0;
    }
    // Unsuppress all code breakpoints
    if (!env->cregs.CR_DBGOPTIN) {
        env->eflags |= (env->cregs.CR_SAVE_TF & HF_TF_MASK);
        // Unsuppress monitor_trap_flag, LBR_generation
    }

    // FIXME: Fill out this
    if (env->eflags & HF_TF_MASK) {

    }

    tmp_secs_host = load_secs(secs); 
    if (!removeEnclaveEntry(tmp_secs_host)) {  
        //raise_exception(env, EXCP0D_GPF);
    }

    //update_ssa_base();
    env->cregs.CR_ENCLAVE_MODE = false;
    env->cregs.CR_EXIT_MODE = true;

    // Used for tracking function end
    // TODO: RCX <-- CR_NEXT_EIP
    // setEnclaveState(true);
    // Mark State inactive

    CPUState *cs = CPU(x86_env_get_cpu(env));
    tlb_flush(cs, 1);
#if PERF
    int64_t eid;
    eid = tmp_secs_host->eid_reserved.eid_pad.eid;
    qenclaves[eid].stat.mode_switch++;
    qenclaves[eid].stat.tlbflush_n++;
    qenclaves[eid].stat.eexit_n++;
    qenclaves[eid].stat.enclu_n++;
#endif
    cpu_stx_data(env, tmp_gpr, tmp_gpr_host, sizeof(gprsgx_t));
    free(tmp_secs_host); 
    free(tmp_gpr_host); 
    sgx_dbg(trace, "eexit finishes well");
}

// Performs parameter (rbx, rcx) check for EGETKEY
static
void sgx_egetkey_param_check(CPUX86State *env)
{
    keyrequest_t *tmp_keyrequest = (keyrequest_t *)env->regs[R_EBX];
    uint64_t *outputdata = (uint64_t *)env->regs[R_ECX];
    perm_check_t rbx_page_perm = { true, false, true, false }; // READ permission
    perm_check_t rcx_page_perm = { false, true, false, true }; // WRITE permission

    sgx_egetkey_common_check(env, (uint64_t *)tmp_keyrequest, 128, rbx_page_perm);
    sgx_egetkey_common_check(env, outputdata, 16, rcx_page_perm);

    keyrequest_t *tmp_keyrequest_host = cpu_ldx_data(env, tmp_keyrequest, sizeof(keyrequest_t)); 

    // Verify RESERVED spaces in KEYREQUEST are valid
    if ((tmp_keyrequest_host->reserved1 != 0)
        || (tmp_keyrequest_host->keypolicy.reserved != 0)) {
        sgx_dbg(trace, "keyrequest reserved field is not empty");
        raise_exception(env, EXCP0D_GPF);
    }
    free(tmp_keyrequest_host);
}

static inline
void op_bitwise(uint8_t *out, uint8_t *in, size_t nbytes)
{
    int i;
    for (i = 0; i < nbytes; i++)
        out[i] = ~in[i];
}

static inline
void op_and(uint8_t *out, uint8_t *in1, uint8_t *in2, size_t nbytes)
{
    int i;
    for (i = 0; i < nbytes; i++)
        out[i] = in1[i] & in2[i];
}

static inline
void op_or(uint8_t *out, uint8_t *in1, uint8_t *in2, size_t nbytes)
{
    int i;
    for (i = 0; i < nbytes; i++)
        out[i] = in1[i] | in2[i];
}

// EGETKEY instruction
static
void sgx_egetkey(CPUX86State *env)
{
    // RBX: KEYREQUEST (In, EA)
    // RCX: OUTPUTDAYA(KEY) (In, IA)
    sgx_dbg(trace, "egetkey start");  
    keyrequest_t *keyrequest = (keyrequest_t *)env->regs[R_EBX];
    uint64_t *outputdata = (uint64_t *)env->regs[R_ECX];

    // check for parameters
    sgx_egetkey_param_check(env);

    // Hard-coded padding
    uint8_t *pkcs1_5_padding = alloc_pkcs1_5_padding();
    secs_t *tmp_currentsecs = (secs_t *)env->cregs.CR_ACTIVE_SECS;

    // Main egetkey operation
    attributes_t sealing_mask, tmp_attributes;

    keyrequest_t *keyrequest_host = cpu_ldx_data(env, keyrequest, sizeof(keyrequest_t)); 
    secs_t *tmp_currentsecs_host = load_secs(tmp_currentsecs); 

    sealing_mask = attr_create(0x03L, 0x0L);
    op_or((uint8_t *)&tmp_attributes,
          (uint8_t *)&keyrequest_host->attributeMask,
          (uint8_t *)&sealing_mask,
          16);

    op_and((uint8_t *)&tmp_attributes,
           (uint8_t *)&tmp_attributes,
           (uint8_t *)&tmp_currentsecs_host->attributes,
           16);

    miscselect_t tmp_miscselect;
    op_and((uint8_t *)&tmp_miscselect,
           (uint8_t *)&tmp_currentsecs_host->miscselect,
           (uint8_t *)&keyrequest_host->miscmask, 4);

    // TODO
    sgx_dbg(trace, "tmp_miscselect %x", tmp_miscselect);
    // TODO
    sgx_dbg(trace, "tmp_currentsecs %x", tmp_currentsecs_host->miscselect);
    // TODO
    sgx_dbg(trace, "keyrequest->miscmask %x", keyrequest_host->miscmask);
    sgx_dbg(trace, "tmp_currentsecs->attributes %x", tmp_currentsecs_host->attributes);
    keydep_t keydep;
    memset(&keydep, 0, sizeof(keydep_t));

    switch (keyrequest_host->keyname) {
        case SEAL_KEY: {
            if (memcmp(keyrequest_host->cpusvn, env->cregs.CR_CPUSVN, 16) > 0) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_CPUSVN;
                sgx_dbg(warn, "ERR_SGX_INVALID_CPUSVN");
                goto _EXIT;
            }

            if (keyrequest_host->isvsvn > tmp_currentsecs_host->isvsvn) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_ISVSVN;
                sgx_dbg(warn, "ERR_SGX_INVALID_ISVSVN");
                goto _EXIT;
            }

            // Include enclave identity
            uint8_t tmp_mrEnclave[32];
            memset(tmp_mrEnclave, 0, 32);
            if (keyrequest_host->keypolicy.mrenclave == 1)
                memcpy(tmp_mrEnclave, tmp_currentsecs_host->mrEnclave, 32);

            // Include enclave author
            uint8_t tmp_mrSigner[32];
            memset(tmp_mrSigner, 0, 32);
            if (keyrequest_host->keypolicy.mrsigner == 1)
                memcpy(tmp_mrSigner, tmp_currentsecs_host->mrSigner, 32);

            // fillin keydep
            keydep.keyname   = SEAL_KEY;
            keydep.isvprodID = tmp_currentsecs_host->isvprodID;
            keydep.isvsvn    = tmp_currentsecs_host->isvsvn;
            memcpy(keydep.ownerEpoch,      env->cregs.CSR_SGX_OWNEREPOCH,                  16);
            memcpy(&keydep.attributes,     &tmp_attributes,                                16);
            memcpy(&keydep.attributesMask, &keyrequest_host->attributeMask,                16);
            memcpy(keydep.mrEnclave,       tmp_mrEnclave,                                  32);
            memcpy(keydep.mrSigner,        tmp_mrSigner,                                   32);
            memcpy(keydep.keyid,           keyrequest_host->keyid,                         32);
            memcpy(keydep.seal_key_fuses,  env->cregs.CR_SEAL_FUSES,                       16);
            memcpy(keydep.cpusvn,          keyrequest_host->cpusvn,                        16);
            memcpy(keydep.padding,         tmp_currentsecs_host->eid_reserved.eid_pad.padding, 352);
            memcpy(&keydep.miscselect,     &tmp_miscselect,                                 4);
            op_bitwise((uint8_t *)&keydep.miscmask, (uint8_t *)&keyrequest_host->miscmask,  4);

            break;
        }
        case REPORT_KEY: {
            sgx_msg(info, "get report key.");
            // fillin keydep
            keydep.keyname   = REPORT_KEY;
            keydep.isvprodID = 0;
            keydep.isvsvn    = 0;
            memcpy(keydep.ownerEpoch,      env->cregs.CSR_SGX_OWNEREPOCH,  16);
            memcpy(&keydep.attributes,     &tmp_currentsecs_host->attributes,   16);
            memset(&keydep.attributesMask, 0,                              16);
            memcpy(keydep.mrEnclave,       tmp_currentsecs_host->mrEnclave,     32);
            memset(keydep.mrSigner,        0,                              32);
            memcpy(keydep.keyid,           keyrequest_host->keyid,         32);
            memcpy(keydep.seal_key_fuses,  env->cregs.CR_SEAL_FUSES,       16);
            memcpy(keydep.cpusvn,          env->cregs.CR_CPUSVN,           16);
            memcpy(keydep.padding,         pkcs1_5_padding,               352);
            memcpy(&keydep.miscselect,     &tmp_miscselect,                 4);
            memset(&keydep.miscmask,       0,                               4);

            break;
        }
        case LAUNCH_KEY: {
            // Check enclave has launch capability
            if (tmp_currentsecs_host->attributes.einittokenkey == 0) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_ATTRIBUTE;
                goto _EXIT;
            }

            if (memcmp(keyrequest_host->cpusvn, env->cregs.CR_CPUSVN, 16) > 0) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_CPUSVN;
                sgx_dbg(warn, "ERR_SGX_INVALID_CPUSVN");
                goto _EXIT;
            }

            if (keyrequest_host->isvsvn > tmp_currentsecs_host->isvsvn) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_ISVSVN;
                sgx_dbg(warn, "ERR_SGX_INVALID_ISVSVN");
                goto _EXIT;
            }

            // fillin keydep
            keydep.keyname   = LAUNCH_KEY;
            keydep.isvprodID = tmp_currentsecs_host->isvprodID;
            keydep.isvsvn    = tmp_currentsecs_host->isvsvn;
            memcpy(keydep.ownerEpoch,      env->cregs.CSR_SGX_OWNEREPOCH,  16);
            memcpy(&keydep.attributes,     &tmp_attributes,                16);
            memset(&keydep.attributesMask, 0,                              16);
            memset(keydep.mrEnclave,       0,                              32);
            memset(keydep.mrSigner,        0,                              32);
            memcpy(keydep.keyid,           keyrequest_host->keyid,         32);
            memcpy(keydep.seal_key_fuses,  env->cregs.CR_SEAL_FUSES,       16);
            memcpy(keydep.cpusvn,          keyrequest_host->cpusvn,        16);
            // XXX: Should use hard code padding here, spec could be wrong.
            memcpy(keydep.padding,         pkcs1_5_padding,               352);
            memcpy(&keydep.miscselect,     &tmp_miscselect,                 4);
            memset(&keydep.miscmask,       0,                               4);
            break;
        }
        case PROVISION_KEY: {
            // Check enclave has provisioning capability
            if (tmp_currentsecs_host->attributes.provisionkey == 0) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_ATTRIBUTE;
                sgx_dbg(warn, "secs.attributes.provisionkey == 0");
                goto _EXIT;
            }

            if (memcmp(keyrequest_host->cpusvn, env->cregs.CR_CPUSVN, 16) > 0) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_CPUSVN;
                sgx_dbg(warn, "ERR_SGX_INVALID_CPUSVN");
                goto _EXIT;
            }

            if (keyrequest_host->isvsvn > tmp_currentsecs->isvsvn) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_ISVSVN;
                sgx_dbg(warn, "ERR_SGX_INVALID_ISVSVN");
                goto _EXIT;
            }

            // Fillin keydep */
            keydep.keyname   = PROVISION_KEY;
            keydep.isvprodID = tmp_currentsecs_host->isvprodID;
            keydep.isvsvn    = keyrequest_host->isvsvn;
            memset(keydep.ownerEpoch,      0,                                              16);
            memcpy(&keydep.attributes,     &tmp_attributes,                                16);
            memcpy(&keydep.attributesMask, &keyrequest_host->attributeMask,                16);
            memset(keydep.mrEnclave,       0,                                              32);
            memcpy(keydep.mrSigner,        tmp_currentsecs_host->mrSigner,                 32);
            memset(keydep.keyid,           0,                                              32);
            memset(keydep.seal_key_fuses,  0,                                              16);
            memcpy(keydep.cpusvn,          keyrequest_host->cpusvn,                        16);
            memcpy(keydep.padding,         tmp_currentsecs_host->eid_reserved.eid_pad.padding, 352);
            memcpy(&keydep.miscselect,     &tmp_miscselect,                                 4);
            op_bitwise((uint8_t *)&keydep.miscmask, (uint8_t *)&keyrequest_host->miscmask,  4);
            break;
        }
        case PROVISION_SEAL_KEY: {
            // Check enclave has provisioning capability
            if (tmp_currentsecs_host->attributes.provisionkey == 0) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_ATTRIBUTE;
                sgx_dbg(warn, "secs.attributes.provisionkey == 0");
                goto _EXIT;
            }

            if (memcmp(keyrequest_host->cpusvn, env->cregs.CR_CPUSVN, 16) > 0) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_CPUSVN;
                sgx_dbg(warn, "ERR_SGX_INVALID_CPUSVN");
                goto _EXIT;
            }

            if (keyrequest_host->isvsvn > tmp_currentsecs_host->isvsvn) {
                env->eflags |= CC_Z;
                env->regs[R_EAX] = ERR_SGX_INVALID_ISVSVN;
                sgx_dbg(warn, "ERR_SGX_INVALID_ISVSVN");
                goto _EXIT;
            }

            // fillin keydep
            keydep.keyname = PROVISION_SEAL_KEY;
            keydep.isvprodID = tmp_currentsecs_host->isvprodID;
            keydep.isvsvn = keyrequest_host->isvsvn;
            memset(keydep.ownerEpoch,      0,                                              16);
            memcpy(&keydep.attributes,     &tmp_attributes,                                16);
            memcpy(&keydep.attributesMask, &keyrequest_host->attributeMask,                16);
            memset(keydep.mrEnclave,       0,                                              32);
            memcpy(keydep.mrSigner,        tmp_currentsecs_host->mrSigner,                 32);
            memset(keydep.keyid,           0,                                              32);
            memcpy(keydep.seal_key_fuses,  env->cregs.CR_SEAL_FUSES,                       16);
            memcpy(keydep.cpusvn,          keyrequest_host->cpusvn,                        16);
            memcpy(keydep.padding,         tmp_currentsecs_host->eid_reserved.eid_pad.padding, 352);
            memcpy(&keydep.miscselect,     &tmp_miscselect,                                 4);
            op_bitwise((uint8_t *)&keydep.miscmask, (uint8_t *)&keyrequest_host->miscmask,       4);
            break;
        }
        default:
            // invalid keyname
            sgx_dbg(warn, "Invalid keyname %d", keyrequest_host->keyname);
            env->regs[R_EAX] = ERR_SGX_INVALID_KEYNAME;
            env->eflags |= CC_Z;
            goto _EXIT;
    }

    uint8_t tmp_key[16]; // REPORTKEY generated by instruction
    // Calculate the final derived key and output
    sgx_derivekey(&keydep, tmp_key);
    cpu_stx_data(env, (uint8_t *)outputdata, tmp_key, 16); 

#if DEBUG
    {
        sgx_msg(info, "Get key:");
        int l;
		for (l = 0; l < 16; l++)
            fprintf(stderr, "%02X", tmp_key[l]);
            //fprintf(stderr, "%02X", (unsigned char *)outputdata[l]);
        fprintf(stderr, "\n");
    }
#endif

    env->regs[R_EAX] = 0;
    env->eflags &= ~CC_Z;
_EXIT:
    // clear flags : CF, PF, AF, OF, SF
    env->eflags &= ~(CC_C | CC_P | CC_A | CC_S | CC_O);

    env->cregs.CR_CURR_EIP = env->cregs.CR_NEXT_EIP;
    env->cregs.CR_ENC_INSN_RET = true;
#if PERF
    int64_t eid;
    eid = tmp_currentsecs_host->eid_reserved.eid_pad.eid;
    qenclaves[eid].stat.egetkey_n++;
    qenclaves[eid].stat.enclu_n++;
#endif
    free(keyrequest_host);
    free(tmp_currentsecs_host);
    sgx_dbg(trace, "egetkey finishes well");
}

static
void sgx_emodpe(CPUX86State *env)
{
    // RBX: secinfo addr(IN)
    // RCX: Destination EPC addr (IN)
    uint64_t sec_index = 0;
    uint64_t epc_index = 0;
    secinfo_t *scratch_secinfo;

    secinfo_t *tmp_secinfo; 
    tmp_secinfo = (secinfo_t *) env->regs[R_EBX]; 
    epc_t *destPage = (epc_t *) env->regs[R_ECX]; 

    sgx_dbg( trace, "emodpe called well");
    sgx_dbg( trace, "%p, %p\n", (void*)tmp_secinfo, destPage);
 
    if(!is_aligned(tmp_secinfo, SECINFO_ALIGN_SIZE)) {
	sgx_dbg(err, "Failed to check alignment: %p on %d bytes", tmp_secinfo, SECINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "emodpe SECINFO alignment well");

    if(!is_aligned(destPage, PAGE_SIZE)) {
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "emodpe EPC alignment well");

    if (((uint64_t)tmp_secinfo < env->cregs.CR_ELRANGE[0])
            || ((uint64_t)tmp_secinfo >= (env->cregs.CR_ELRANGE[0] + env->cregs.CR_ELRANGE[1]))) {
            sgx_dbg(trace, "Secinfo is not in CR_ELRANGE: %lx", (long unsigned int)tmp_secinfo);
            raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "Secinfo is in CR_ELRANGE");

    if (((uint64_t)destPage < env->cregs.CR_ELRANGE[0])
            || ((uint64_t)destPage >= (env->cregs.CR_ELRANGE[0] + env->cregs.CR_ELRANGE[1]))) {
            sgx_dbg(trace, "EPC addr is not in CR_ELRANGE: %lx", (long unsigned int)destPage);
            raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg(trace, "EPC addr is in CR_ELRANGE");

    check_linaddr_within_epc(tmp_secinfo, env);
    check_linaddr_within_epc(destPage, env);
    sgx_dbg(trace, "check_linaddr_within_epc");

    sec_index = epcm_linsearch(tmp_secinfo, env);
    epcm_entry_t *epcm_secinfo = &epcm[sec_index]; 

    if(epcm_secinfo->valid == 0 || epcm_secinfo->read == 0 || epcm_secinfo->pending != 0 ||
       epcm_secinfo->modified != 0 || epcm_secinfo->blocked != 0 || epcm_secinfo->page_type != PT_REG ||
       epcm_secinfo->enclave_secs != env->cregs.CR_ACTIVE_SECS || epcm_secinfo->enclave_addr == env->regs[R_EBX]) {
            sgx_dbg(trace, "EPCM invalid");
            raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg(trace, "EPCM valid");

    scratch_secinfo = cpu_ldx_data(env, tmp_secinfo, sizeof(secinfo_t));

    is_reserved_zero(&(scratch_secinfo->reserved), sizeof(((secinfo_t *)0)->reserved), env);
    sgx_dbg(trace, "reserved zero check");

    //check security attributes of the EPC page
    epc_index = epcm_linsearch((void*)destPage, env);
    epcm_entry_t *epcm_epc = &epcm[epc_index];

    if(epcm_epc->valid == 0 || epcm_epc->pending != 0 || epcm_epc->modified != 0 ||
       epcm_epc->blocked != 0 || epcm_epc->page_type != PT_REG ||
       epcm_epc->enclave_secs != env->cregs.CR_ACTIVE_SECS) {
            sgx_dbg(trace, "EPCM invalid");
            raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg(trace, "EPCM valid");
    //TODO: Check the EPC page for concurrency 

    // Re-check attributes of the EPC page
    if(epcm_epc->valid == 0 || epcm_epc->pending != 0 || epcm_epc->modified != 0 || 
       epcm_epc->blocked != 0 || epcm_epc->page_type != PT_REG || 
       epcm_epc->enclave_secs != env->cregs.CR_ACTIVE_SECS || 
       epcm_epc->enclave_addr != env->regs[R_ECX]) {
            sgx_dbg(trace, "EPCM invalid");
            raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg(trace, "EPCM valid");
    
    //check for mis-configured SECINFO flags
    if(epcm_secinfo->read == 0 && scratch_secinfo->flags.r == 0 && scratch_secinfo->flags.w != 0) {
        sgx_dbg(trace, "error: check for mis-configured SECINFO flags");
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg(trace, "check for mis-configured SECINFO flags");

    //update EPCM permissions
    sgx_dbg( trace, "EPCM permission : %d, %d, %d", epcm_epc->read, epcm_epc->write, epcm_epc->execute );
    epcm_epc->read |= scratch_secinfo->flags.r;
    epcm_epc->write |= scratch_secinfo->flags.w;
    epcm_epc->execute |= scratch_secinfo->flags.x;
    sgx_dbg( trace, "update EPCM permission : %d, %d, %d", epcm_epc->read, epcm_epc->write, epcm_epc->execute );

    cpu_stx_data( env, tmp_secinfo, scratch_secinfo, sizeof(secinfo_t));
    sgx_dbg(trace, "after cpu_stx_data");

    free( scratch_secinfo);

    // next instruction
    env->cregs.CR_CURR_EIP = env->cregs.CR_NEXT_EIP;
    env->cregs.CR_ENC_INSN_RET = true;
}

// EREPORT instruction
static
void sgx_ereport(CPUX86State *env)
{
    // RBX: TARGETINFO(In, EA)
    // RCX: REPORTDATA(In, EA)
    // RDX: Address_where_report is writted to in an Output Data (In)
    sgx_dbg(trace, "ereport point starts");
    secs_t *tmp_currentsecs = (secs_t *)env->cregs.CR_ACTIVE_SECS;// Address of the SECS for currently exec enclave
    keydep_t tmp_keydependencies; // Temp space Key derivation
    uint8_t tmp_reportkey[16]; // REPORTKEY generated by instruction
    report_t tmp_report;
    secs_t *tmp_secs_host = load_secs(tmp_currentsecs); 
    /* Storing the Input Values from Registers */
    targetinfo_t *targetinfo = (targetinfo_t *)env->regs[R_EBX];
    targetinfo_t *targetinfo_host = cpu_ldx_data(env, targetinfo, sizeof(targetinfo_t));
    uint64_t *outputdata = (uint64_t *)env->regs[R_EDX];
//    bool tmp_mode64 = (env->efer & MSR_EFER_LMA) && (env->segs[R_CS].flags & DESC_L_MASK);

    perm_check_t rbx_page_perm = { true, false, true, false }; // READ permission
    perm_check_t rdx_page_perm = { false, true, false, true }; // WRITE permission

    sgx_egetkey_common_check(env, (uint64_t *)targetinfo, 128, rbx_page_perm);
    sgx_egetkey_common_check(env, outputdata, 512, rdx_page_perm);

    /* REPORT MAC needs to be computed over data which cannot be modified */
    tmp_report.isvProdID  = tmp_secs_host->isvprodID;
    tmp_report.isvsvn     = tmp_secs_host->isvsvn;
    //TODO
    memcpy(&tmp_report.attributes, &tmp_secs_host->attributes, 16);
    sgx_dbg(trace, "tmp_currentsecs->attributes %x", tmp_secs_host->attributes);
    sgx_dbg(trace, "tmp_report->attributes %x", tmp_report.attributes);
    //TODO
    memcpy(&tmp_report.miscselect,&tmp_secs_host->miscselect,    4);
    //
    memcpy(tmp_report.cpusvn,     env->cregs.CR_CPUSVN,          16);
    memcpy(tmp_report.reportData, (void*)env->regs[R_ECX],       64);
    memcpy(tmp_report.mrenclave,  tmp_secs_host->mrEnclave,    32);
    memcpy(tmp_report.mrsigner,   tmp_secs_host->mrSigner,     32);
    memcpy(tmp_report.keyid,      &(env->cregs.CR_REPORT_KEYID), 32);
    // Set all reserved to 0

    //TODO
    memset(tmp_report.reserved , 0 ,28);
    memset(tmp_report.reserved2, 0, 32);
    memset(tmp_report.reserved3, 0, 96);
    memset(tmp_report.reserved4, 0, 60);

#if DEBUG
    {
	uint8_t report[512];
	memset(report, 0, 512);
    	memcpy(report, (uint8_t *)&tmp_report, 432);
        sgx_msg(info, "Generated report:");
        int k;
        for (k = 0; k < 432; k++)
            fprintf(stderr, "%02X", report[k]);
    }
#endif

    uint8_t *pkcs1_5_padding = alloc_pkcs1_5_padding();

    // key dependencies init
    memset((unsigned char *)&tmp_keydependencies, 0, sizeof(keydep_t));

    /* Derive the Report Key */
    tmp_keydependencies.keyname   = REPORT_KEY;
    tmp_keydependencies.isvprodID = 0;
    tmp_keydependencies.isvsvn    = 0;
    memcpy(tmp_keydependencies.ownerEpoch,      env->cregs.CSR_SGX_OWNEREPOCH,  16);
    memcpy(&tmp_keydependencies.attributes,     &targetinfo_host->attributes,   16);

// TODO

    memset(&tmp_keydependencies.attributesMask, 0,                              16);
    memcpy(tmp_keydependencies.mrEnclave,       targetinfo_host->measurement,   32);
    memset(tmp_keydependencies.mrSigner,        0,                              32);
    memcpy(tmp_keydependencies.keyid,           tmp_report.keyid,               32);
    memcpy(tmp_keydependencies.seal_key_fuses,  env->cregs.CR_SEAL_FUSES,       16);
    memcpy(tmp_keydependencies.cpusvn,          env->cregs.CR_CPUSVN,           16);
    memcpy(&tmp_keydependencies.miscselect,     &targetinfo_host->miscselect,    4);
    memset(&tmp_keydependencies.miscmask,       0,                               4);
    // XXX: should use hard code padding, spec might be wrong.
    memcpy(tmp_keydependencies.padding,         pkcs1_5_padding,               352);

    /* Calculate Derived Key */
    sgx_derivekey(&tmp_keydependencies, (unsigned char *)tmp_reportkey);

#if DEBUG
    {
        sgx_msg(info, "Expected report key:");
        int l;
		for (l = 0; l < 16; l++)
            fprintf(stderr, "%02X", tmp_reportkey[l]);
        fprintf(stderr, "\n");
    }
#endif

    aes_cmac128_context ctx;

    aes_cmac128_starts(&ctx, tmp_reportkey);
    aes_cmac128_update(&ctx, (uint8_t *)&tmp_report, 416);
    aes_cmac128_final(&ctx, tmp_report.mac);

    uint8_t report[512];
    memset(report, 0, 512);
    memcpy(report, (uint8_t *)&tmp_report, 432);

    cpu_stx_data(env, outputdata, report, 512); 

#if DEBUG
    {
        sgx_msg(info, "Generated report:");
        int k;
        for (k = 0; k < 432; k++)
            fprintf(stderr, "%02X", report[k]);
    }
#endif

    env->cregs.CR_CURR_EIP = env->cregs.CR_NEXT_EIP;
    env->cregs.CR_ENC_INSN_RET = true;
#if PERF
    int64_t eid;
    eid = tmp_secs_host->eid_reserved.eid_pad.eid;
    qenclaves[eid].stat.ereport_n++;
    qenclaves[eid].stat.enclu_n++;
#endif
    free(targetinfo_host);
    free(tmp_secs_host);
    sgx_dbg(trace, "ereport finishes well");
}

static
void sgx_eresume(CPUX86State *env)
{

    // RBX: Address of TCS (In)
    // RCX: Address of AEP(In)

    tcs_t *tcs;
    tcs_t *tcs_host; 
    uint64_t *aep;
    bool tmp_mode64;
    uint64_t tmp_fsbase;
    uint64_t tmp_fslimit;
    uint64_t tmp_gsbase;
    uint64_t tmp_gslimit;
    uint64_t tmp_ssa;
    uint64_t tmp_gpr;
    gprsgx_t *tmp_gpr_host; 
    uint64_t eid;
    uint64_t tmp_target;
    uint16_t index_gpr;
    uint16_t index_tcs;
    operation = eresume;

    env->cregs.CR_IS_IN_ERESUME = true; //cch: added for test

    sgx_dbg(trace, "Current ESP: %lx   EBP: %lx", env->regs[R_ESP], env->regs[R_EBP]);
    // Store the inputs
    aep = (uint64_t *)env->regs[R_ECX];
    tcs = (tcs_t *)env->regs[R_EBX];
    tcs_host = cpu_ldx_data(env, tcs, sizeof(tcs_t)); //cch: should be freed later. should be copied to original
    index_tcs = epcm_linsearch(tcs, env);
    tmp_mode64 = (env->efer & MSR_EFER_LMA) && (env->segs[R_CS].flags & DESC_L_MASK);

#if DEBUG
    sgx_dbg(trace, "INDEX_TCS: %d Mode64: %d", index_tcs, tmp_mode64);
#endif
    // Also Need to check DS[S] == 1 and DS[11] and DS[10]
    if ((!tmp_mode64) && ((&env->segs[R_DS] != NULL) ||
        (!extractBitVal(env->segs[R_DS].selector, 11) &&
        extractBitVal(env->segs[R_DS].selector, 10) &&
        env->segs[R_DS].flags & DESC_S_MASK))) {
        raise_exception(env, EXCP0D_GPF);
    }

    // Check that CS, SS, DS, ES.base is 0
    if (!tmp_mode64) {
        if (((&env->segs[R_CS] != NULL) && (env->segs[R_CS].base != 0))
           || (env->segs[R_DS].base != 0)) {
            raise_exception(env, EXCP0D_GPF);
        }

        if ((&env->segs[R_ES] != NULL) && (env->segs[R_ES].base != 0)) {
            raise_exception(env, EXCP0D_GPF);
        }

        if ((&env->segs[R_SS] != NULL) && (env->segs[R_SS].base != 0)) {
            raise_exception(env, EXCP0D_GPF);
        }

        if ((&env->segs[R_SS] != NULL) &&
                   ((env->segs[R_SS].flags & DESC_B_MASK) == 0)) {
            raise_exception(env, EXCP0D_GPF);
        }
    }

    // Check if DS:RBX is not 4KByte Aligned
    if (!is_aligned(tcs, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tcs, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // Temporarily block
    check_linaddr_within_epc(tcs, env); 
    // Check if AEP is canonical
    if (tmp_mode64) {
        is_canonical((uint64_t)aep, env);
    }

    // TODO - Check concurrency of operations on TCS

    // Check Validity and whether access has been blocked
    epcm_invalid_check(&epcm[index_tcs], env);
    epcm_blocked_check(&epcm[index_tcs], env);
#if DEBUG
    sgx_dbg(trace, "Index_TCS  valid : %d Blocked : %d",
               epcm[index_tcs].valid, epcm[index_tcs].blocked);
    // Async Exit pointer -- make a struct of registers
    sgx_dbg(trace, "EPCM[index_tcs] %lu tcs %lu page_type %d",
            epcm[index_tcs].enclave_addr, (uint64_t)tcs,
                       epcm[index_tcs].page_type);
    // Check for Address and page type
#endif

    epcm_enclave_addr_check(&epcm[index_tcs], (uint64_t)tcs, env);
    epcm_page_type_check(&epcm[index_tcs], PT_TCS, env);

    // Alignment OFSBASGX with Page Size
    if (!is_aligned((void *)tcs_host->ofsbasgx, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                (void *)tcs_host->ofsbasgx, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    if (!is_aligned((void *)tcs_host->ogsbasgx, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                (void *)tcs_host->ogsbasgx, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // Get the address of SECS for TCS - Implicit Access - Cached by the processor - EPC
    // Obtain the Base and Limits of FS and GS Sections
    // Check proposed FS/GS segments fall within DS
    secs_t *tmp_secs =  get_secs_address(&epcm[index_tcs]);//Change when the ENCLS is implemented - pag
    secs_t *tmp_secs_host = load_secs(tmp_secs); 
    // Alignment - OSSA With Page Size
    if (!is_aligned((void *)(tmp_secs_host->baseAddr + tcs_host->ossa), PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                (void *)(tmp_secs_host->baseAddr + tcs_host->ossa), PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // Ensure that the FLAGS field in the TCS does not have any reserved bits set
    checkReservedBits((uint64_t *)&tcs_host->flags, 0xFFFFFFFFFFFFFFFEL, env);
    eid = tmp_secs_host->eid_reserved.eid_pad.eid;
    // SECS must exist and enclave must have previously been EINITted
    if ((tmp_secs == NULL) && !checkEINIT(eid)) {// != NULL taken care of earlier itself
        raise_exception(env, EXCP0D_GPF);
    }
   // make sure the logical processor’s operating mode matches the enclave
    if (tmp_secs_host->attributes.mode64bit != tmp_mode64) {
        raise_exception(env, EXCP0D_GPF);
    }
    // OSFXSR == 0 ?
    if (!(env->cr[4] & CR4_OSFXSR_MASK)) {
        raise_exception(env, EXCP0D_GPF);
    }
    // Check for legal values of SECS.ATTRIBUTES.XFRM
    if (!(env->cr[4] & CR4_OSXSAVE_MASK)) {
        if (tmp_secs_host->attributes.xfrm != 0x03) {
            raise_exception(env, EXCP0D_GPF);
        } else
            if ((tmp_secs_host->attributes.xfrm & env->xcr0) ==
                   tmp_secs_host->attributes.xfrm) {
               raise_exception(env, EXCP0D_GPF);
        }
    }
    // Make sure the SSA contains at least one more frame
#if DEBUG
    sgx_dbg(trace, "SSA cssa first check %d", tcs_host->cssa);
#endif
    if (tcs_host->cssa == 0) {
        raise_exception(env, EXCP0D_GPF);
    }

    // Compute linear address of SSA frame
    tmp_ssa = (tcs_host->ossa) + (tmp_secs_host->baseAddr + PAGE_SIZE * tmp_secs_host->ssaFrameSize * (tcs_host->cssa - 1));
    // XXX: unused.
	//tmp_xsize = compute_xsave_frame_size(env, tmp_secs->attributes);

#if DEBUG
    //sgx_dbg(trace, "SSA_: %lx  XSize: %lu", tmp_ssa, tmp_xsize);
#endif

// TODO: Implement XSAVE/XSTOR related spec

    // Compute Address of GPR Area
    tmp_gpr = tmp_ssa + PAGE_SIZE * (tmp_secs_host->ssaFrameSize) - sizeof(gprsgx_t);

    index_gpr = epcm_linsearch((void *)tmp_gpr, env); 

    // Temporarily block
    check_linaddr_within_epc((void *)tmp_gpr, env); 
    // Check for validity and block
    epcm_invalid_check(&epcm[index_gpr], env);
    epcm_blocked_check(&epcm[index_gpr], env);
    // XXX: Spec might be wrong, see comment is sgx_eenter.
    // In second parameter, use tmp_ssa instead of tmp_gpr for now.
    epcm_field_check(&epcm[index_gpr], (uint64_t)tmp_ssa, PT_REG,
                     (uint64_t)epcm[index_tcs].enclave_secs, env);

    if (!epcm[index_gpr].read || !epcm[index_gpr].write) {
        raise_exception(env, EXCP0D_GPF);
    }
    if (!tmp_mode64) {
        checkWithinDSSegment(env, tmp_gpr + sizeof(env->regs[R_EAX]));
    }

    // GetPhysical Address of TMP_GPR
    env->cregs.CR_GPR_PA = tmp_gpr;

#if DEBUG
    //sgx_dbg(trace, "Physical Address obtained cr_gpr_a: %lp", (void *)env->cregs.CR_GPR_PA);
#endif
    tmp_gpr_host = cpu_ldx_data(env, tmp_gpr, sizeof(gprsgx_t)); //cch: tmp_gpr_host should be copied to original tmp_gpr and then freed later

    tmp_target = tmp_gpr_host->rip;
    if (tmp_mode64) {
        is_canonical(tmp_target, env);
    } else {
        if (tmp_target > env->segs[R_CS].limit) {
            raise_exception(env, EXCP0D_GPF);
        }
    }
    if (!tmp_mode64) {
        tmp_fsbase = tcs_host->ofsbasgx + tmp_secs_host->baseAddr;
        tmp_fslimit = tmp_fsbase + tcs_host->fslimit;
        tmp_gsbase = tcs_host->ogsbasgx + tmp_secs_host->baseAddr;
        tmp_gslimit = tmp_gsbase + tcs_host->gslimit;

        // if FS wrap-around, make sure DS has no holes
        if (tmp_fslimit < tmp_fsbase) {
            if (env->segs[R_DS].limit < DSLIMIT) {
                raise_exception(env, EXCP0D_GPF);
            } else
                if (tmp_fslimit > env->segs[R_DS].limit) {
                       raise_exception(env, EXCP0D_GPF);
            }
        }
        // if GS wrap-around, make sure DS has no holes
        if (tmp_gslimit < tmp_gsbase) {
            if (env->segs[R_DS].limit < DSLIMIT) {
                raise_exception(env, EXCP0D_GPF);
            } else
               if (tmp_gslimit > env->segs[R_DS].limit) {
                       raise_exception(env, EXCP0D_GPF);
            }
        }
    } else {
        tmp_fsbase = tcs_host->ofsbasgx + tmp_secs_host->baseAddr;
        tmp_gsbase = tcs_host->ogsbasgx + tmp_secs_host->baseAddr;

        is_canonical((uint64_t)(void*)tmp_fsbase, env);
        is_canonical((uint64_t)(void*)tmp_gsbase, env);
    }

    env->cregs.CR_ENCLAVE_MODE = true;
    env->cregs.CR_ACTIVE_SECS = (uint64_t)tmp_secs;
    env->cregs.CR_ELRANGE[0] = tmp_secs_host->baseAddr;
    env->cregs.CR_ELRANGE[1] = tmp_secs_host->size;

    // Save state for possible AEXs
    env->cregs.CR_TCS_LA = (uint64_t)tcs;
    env->cregs.CR_TCS_PH = return_hostaddr(env, (uint64_t)tcs);
    sgx_dbg(trace, "CR_TCS_LA: %p, CR_TCS_PH: %p", env->cregs.CR_TCS_LA, env->cregs.CR_TCS_PH); 
    env->cregs.CR_AEP = (uint64_t)aep;
    //sgx_dbg(trace, "CR_AEP: %p", env->cregs.CR_AEP); 

    // Save the hidden portions of FS and GS
    env->cregs.CR_SAVE_FS.selector = env->segs[R_FS].selector;
    env->cregs.CR_SAVE_FS.base = env->segs[R_FS].base;
    env->cregs.CR_SAVE_FS.limit = env->segs[R_FS].limit;
    env->cregs.CR_SAVE_FS.flags = env->segs[R_FS].flags;

    env->cregs.CR_SAVE_GS.selector = env->segs[R_GS].selector;
    env->cregs.CR_SAVE_GS.base = env->segs[R_GS].base;
    env->cregs.CR_SAVE_GS.limit = env->segs[R_GS].limit;
    env->cregs.CR_SAVE_GS.flags = env->segs[R_GS].flags;

    // If XSAVE is enabled, save XCR0 and replace it with SECS.ATTRIBUTES.XFRM
    if ((env->cr[4] & CR4_OSXSAVE_MASK)) {
        env->cregs.CR_SAVE_XCR0 = env->xcr0;
        env->xcr0 = tmp_secs_host->attributes.xfrm;
    }

    // Retrieved IP from tmp_ssa assigned to EIP
    env->eip = tmp_target;
    env->cregs.CR_CURR_EIP = env->eip;

    sgx_dbg(trace, "Restart from here: %lx", env->eip);

    // Restore GPRs
    restoreGPRs((gprsgx_t *)tmp_gpr_host, env); 
    env->cregs.CR_EXIT_EIP = ((gprsgx_t *)tmp_gpr_host)->SAVED_EXIT_EIP; 

    // Pop the Stack Frame
    tcs_host->cssa = tcs_host->cssa - 1;

    // Do the FS/GS swap
    env->segs[R_FS].base = tmp_fsbase;
    env->segs[R_FS].limit = tcs_host->fslimit;

    env->segs[R_FS].flags |= 0x01;
    env->segs[R_FS].flags |= env->segs[R_DS].flags & DESC_W_MASK;
    env->segs[R_FS].flags |= DESC_S_MASK;
    env->segs[R_FS].flags |= env->segs[R_DS].flags & DESC_DPL_MASK;
    env->segs[R_FS].flags |= DESC_G_MASK;
    env->segs[R_FS].flags |= DESC_B_MASK;
    env->segs[R_FS].flags |= DESC_P_MASK;
    env->segs[R_FS].flags |= env->segs[R_DS].flags & DESC_AVL_MASK;
    env->segs[R_FS].flags |= env->segs[R_DS].flags & DESC_L_MASK;
    env->segs[R_FS].selector = 0x0B;

    env->segs[R_GS].base = tmp_gsbase;
    env->segs[R_GS].limit = tcs_host->gslimit;

    env->segs[R_GS].flags |= 0x01;
    env->segs[R_GS].flags |= env->segs[R_DS].flags & DESC_W_MASK;
    env->segs[R_GS].flags |= DESC_S_MASK;
    env->segs[R_GS].flags |= env->segs[R_DS].flags & DESC_DPL_MASK;
    env->segs[R_GS].flags |= DESC_G_MASK;
    env->segs[R_GS].flags |= DESC_B_MASK;
    env->segs[R_GS].flags |= DESC_P_MASK;
    env->segs[R_GS].flags |= env->segs[R_DS].flags & DESC_AVL_MASK;
    env->segs[R_GS].flags |= env->segs[R_DS].flags & DESC_L_MASK;
    env->segs[R_GS].selector = 0x0B;

    sgx_dbg(trace, "EBP: %lx  ESP: %lx", env->regs[R_EBP], env->regs[R_ESP]);

    // FIXME: Not needed mostly
    //update_ssa_base();

    env->cregs.CR_DBGOPTIN = tcs_host->flags.dbgoptin;
    // Supress all code breakpoints -- Not Needed as of now
    /*
    if(!env->cregs.CR_DBGOPTIN) {
        env->cregs.CR_SAVE_TF = env->eflags & HF_TF_MASK;
        env->eflags = env->eflags & ~(HF_TF_MASK);
        // Support Monitor Trap Flag
        // Clear All pending debug exceptions
        // Clear pending MTF VM EXIT
    } else {
        if (env->eflags & HF_TF_MASK) {
        }
       // if ( vmcs.mtf) {
          }
    } */

    // Considering QEMU TB flow for conditional statements
    env->cregs.CR_ENC_INSN_RET = true;

    CPUState *cs = CPU(x86_env_get_cpu(env));
    tlb_flush(cs, 1);
#if PERF
    qenclaves[eid].stat.mode_switch++;
    qenclaves[eid].stat.tlbflush_n++;
    qenclaves[eid].stat.eresume_n++;
    qenclaves[eid].stat.enclu_n++;
#endif
    cpu_stx_data(env, tcs, tcs_host, sizeof(tcs_t));
    free(tcs_host); 
    free(tmp_secs_host); 
    free(tmp_gpr_host); 
    sgx_dbg(trace, "eresume finishes well");
    env->cregs.CR_IS_IN_ERESUME = false; //cch: added for test
    return;
}

static
const char *enclu_cmd_to_str(long cmd) {
    switch (cmd) {
    case ENCLU_EACCEPT:     return "EACCEPT";
    case ENCLU_EACCEPTCOPY: return "EACCEPTCOPY";
    case ENCLU_EENTER:      return "EENTER";
    case ENCLU_EEXIT:       return "EEXIT";
    case ENCLU_EGETKEY:     return "EGETKEY";
    case ENCLU_EMODPE:       return "EMODPE";
    case ENCLU_EREPORT:     return "EREPORT";
    case ENCLU_ERESUME:     return "ERESUME";
    }
    return "UNKONWN";
}

void helper_sgx_enclu(CPUX86State *env, uint64_t next_eip)
{
    sgx_dbg(trace,
            "(%-13s), EBX=0x%08"PRIx64", "
            "RCX=0x%08"PRIx64", RDX=0x%08"PRIx64,
            enclu_cmd_to_str(env->regs[R_EAX]),
            env->regs[R_EBX],
            env->regs[R_ECX],
            env->regs[R_EDX]);
    switch (env->regs[R_EAX]) {
        case ENCLU_EACCEPT:
            env->cregs.CR_NEXT_EIP = next_eip;
            sgx_eaccept(env);
            break;
        case ENCLU_EACCEPTCOPY:
            env->cregs.CR_NEXT_EIP = next_eip;
            sgx_eacceptcopy(env);
            break;
        case ENCLU_EENTER:
            env->cregs.CR_NEXT_EIP = next_eip;
            sgx_eenter(env);
            break;
        case ENCLU_EEXIT:
            env->cregs.CR_NEXT_EIP = next_eip;
            sgx_eexit(env);
/*
#if PERF
            if(env->regs[R_EBX] == 0)   //print_perf_count is called only when EEXIT(NULL)
                print_perf_count(env);
#endif
*/
            break;
        case ENCLU_EGETKEY:
            env->cregs.CR_NEXT_EIP = next_eip;
            sgx_egetkey(env);
            break;
        case ENCLU_EMODPE:
            env->cregs.CR_NEXT_EIP = next_eip;
            sgx_emodpe(env);
            break;
        case ENCLU_EREPORT:
            env->cregs.CR_NEXT_EIP = next_eip;
            sgx_ereport(env);
            break;
        case ENCLU_ERESUME:
            sgx_eresume(env);
            break;

        default:
            sgx_err("not implemented yet");
    }
}

// ENCLS instruction implementation.

// popcnt for ECREATE error check
static
int popcnt(uint64_t v)
{
    unsigned int v1, v2;

    v1 = (unsigned int)(v & 0xFFFFFFFF);
    v1 -= (v1 >> 1) & 0x55555555;
    v1 = (v1 & 0x33333333) + ((v1 >> 2) & 0x33333333);
    v1 = (v1 + (v1 >> 4)) & 0x0F0F0F0F;
    v2 = (unsigned int)(v >> 32);
    v2 -= (v2 >> 1) & 0x55555555;
    v2 = (v2 & 0x33333333) + ((v2 >> 2) & 0x33333333);
    v2 = (v2 + (v2 >> 4)) & 0x0F0F0F0F;

    return ((v1 * 0x01010101) >> 24) + ((v2 * 0x01010101) >> 24);
}

// Increments counter by value
static
void LockedXAdd(uint64_t* counter, uint64_t value)
{
    /* Method 1
    asm volatile("lock; xaddl %%eax, %2;"
                  :"=a" (value)                  //Output
                  :"a" (value), "m" (*counter)  //Input
                  :);
    */
    __sync_add_and_fetch(counter, value);
}

/* TODO
   static void compute_xsave_size(void)
   {
   return;
   }
*/

static
epc_t *cpu_load_pi_srcpge(CPUX86State *env, pageinfo_t *pi)
{
    target_ulong addr = (target_ulong)pi + offsetof(pageinfo_t, srcpge);
    return (epc_t *)cpu_ldq_data(env, addr);
}

static
secs_t *cpu_load_pi_secs(CPUX86State *env, pageinfo_t *pi)
{
    target_ulong addr = (target_ulong)pi + offsetof(pageinfo_t, secs);
    return (secs_t *)cpu_ldq_data(env, addr);
}

#ifdef THREAD_PROTECTION
static
tcs_t *cpu_load_pi_tcs(CPUX86State *env, pageinfo_t *pi)
{
    target_ulong addr = (target_ulong)pi + offsetof(pageinfo_t, tcs);
    return (tcs_t *)cpu_ldq_data(env, addr);
}
#endif

static
secinfo_t *cpu_load_pi_secinfo(CPUX86State *env, pageinfo_t *pi)
{
    target_ulong addr = (target_ulong)pi + offsetof(pageinfo_t, secinfo);
    return (secinfo_t *)cpu_ldq_data(env, addr);
}

static
void *cpu_load_pi_linaddr(CPUX86State *env, pageinfo_t *pi)
{
    target_ulong addr = (target_ulong)pi + offsetof(pageinfo_t, linaddr);
    return (void *)cpu_ldq_data(env, addr);
}



// ECREATE is the first instruction in the enclave build process.
// In ECREATE, an SECS structure (PAGEINFO.SRCPGE) outside the epc is copied
// into an EPC page (with page type = SECS).
// Also, security measurement (SECS.MRENCLAVE) is initialized with measuring
// ECREATE string, SECS.SSAFRAMESIZE, and SECS.SIZE.
static
void sgx_ecreate(CPUX86State *env)
{
    // RBX: PAGEINFO(In, EA)
    // RCX: EPCPAGE(In, EA)

    enclave_init = true;
    pageinfo_t *pageInfo = (pageinfo_t *)env->regs[R_EBX];
    secs_t *tmp_secs = (secs_t *)env->regs[R_ECX];

    //TEMP Vars
    epc_t *tmp_srcpge;
    secinfo_t *tmp_secinfo;
    void *tmp_linaddr;
    secs_t *tmp_secs_pi;
    secinfo_flags_t tmp_secinfo_flags; 
    uint64_t *tmp_secinfo_reserved; 
    secs_t *tmp_secs_host;   
#ifdef THREAD_PROTECTION
    tcs_t *tmp_tcs;
#endif


    // If RBX is not 32 Byte aligned, then GP(0)
    if (!is_aligned(pageInfo, PAGEINFO_ALIGN_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                pageInfo, PAGEINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    // If RCX is not 4KByte aligned or not within an EPC
    if (!is_aligned(tmp_secs, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_secs, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    // Check secs is in EPC
    check_within_epc(tmp_secs, env);
    

    // set temp variables
    tmp_srcpge  = cpu_load_pi_srcpge(env, pageInfo);
    tmp_secinfo = cpu_load_pi_secinfo(env, pageInfo);
    tmp_secs_pi = cpu_load_pi_secs(env, pageInfo);
    tmp_linaddr = cpu_load_pi_linaddr(env, pageInfo);
#ifdef THREAD_PROTECTION
    tmp_tcs     = cpu_load_pi_tcs(env, pageInfo);
#endif
    

    // If srcpge and secinfo of pageInfo is not 32 Byte aligned, then GP(0)
    if (!is_aligned(tmp_srcpge, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_srcpge, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    if (!is_aligned(tmp_secinfo, SECINFO_ALIGN_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_secinfo, SECINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If linaddr and secs of pageInfo is non-zero, then GP(0)
    if (tmp_linaddr != 0 || tmp_secs_pi != 0) {
        raise_exception(env, EXCP0D_GPF);
    }

#ifdef THREAD_PROTECTION
    if (tmp_tcs != 0) {
        sgx_dbg(err, "TCS field is not zero");
        raise_exception(env, EXCP0D_GPF);
    }
#endif

    // If page type is not secs, then GP(0)
    tmp_secinfo_flags = cpu_load_si_flags(env, tmp_secinfo);
    if (tmp_secinfo_flags.page_type != PT_SECS) { 
        raise_exception(env, EXCP0D_GPF);
    }

    // tmp_secinfo->flags reserved field check. If it is not zero, then GP(0)
    checkReservedBits((uint64_t *)&tmp_secinfo_flags, 0xF8L, env);
    checkReservedBits((uint64_t *)&tmp_secinfo_flags, 0xFFFFFFFFFFFF0000L, env);

    // tmp_secinfo reserved field check. If it is not zero, then GP(0)
    tmp_secinfo_reserved = cpu_load_si_reserved(env, tmp_secinfo); 

    is_reserved_zero(tmp_secinfo_reserved, sizeof(((secinfo_t *)0)->reserved), env);

    uint8_t tmpUpdateField[64];
    uint64_t hash_ecreate = 0x0045544145524345;     // "ECREATE"; for SHA256

    // Copy 4KBytes from source page to EPC page
    cpu_load_n_store(env, tmp_secs, tmp_srcpge, PAGE_SIZE);

    // if epcm[RCX].valid == 1, then GP(0)
    uint16_t index_secs = epcm_search(tmp_secs, env); 
    epcm_valid_check(&epcm[index_secs], env);

    tmp_secs_host = cpu_load_secs(env, tmp_secs);

    // check lower 2bits of XFRM are set
    if ((tmp_secs_host->attributes.xfrm & 0x3) != 0x3) { 
        raise_exception(env, EXCP0D_GPF);
    }

    // TODO : XFRM is illegal -> see 6.7.2.1

    // TODO : Compute the size required to save state of the enclave on async exit
//  uint64_t tmp_xsize;
//  tmp_xsize = compute_xsave_size(tmp_secs->attributes.XFRM) + gpr_size;

    // TODO : Check whether declared area is large enough to hold XSAVE and GPR stat
//  if(tmp_secs->ssaFrameSize * 4096 < tmp_xsize)
//      raise_exception(env, EXCP0D_GPF);


    sgx_dbg(info, "baseAddr: %p, size: %x", tmp_secs_host->baseAddr, tmp_secs_host->size); 

    // ATTRIBUTES MODE64BIT, TMP_SECS SIZE check
    if (tmp_secs_host->attributes.mode64bit == 0) { 
        checkReservedBits((uint64_t *)&tmp_secs_host->baseAddr,
                          0x0FFFFFFFF00000000L, env); 
        checkReservedBits((uint64_t *)&tmp_secs_host->size,
                          0x0FFFFFFFF00000000L, env);
    } else { // tmp_secs->attributes.mode64bit == 1
        is_canonical(tmp_secs_host->baseAddr, env); 
        checkReservedBits((uint64_t *)&tmp_secs_host->size,
                          0x0FFFFFFE000000000L, env);
    }

    // Base addr of enclave is aligned on size
    // TODO : Should be enabled

//    if(tmp_secs->baseAddr & (tmp_secs->size - 1))
//        raise_exception(env, EXCP0D_GPF);


    // Enclave must be at least 8192 bytes and must be power of 2 in bytes
    if ((tmp_secs_host->size < (PAGE_SIZE * 2)) || (popcnt(tmp_secs_host->size) > 1)) {
        sgx_dbg(err, "Invalid SECS.SIZE (less than 8192 or not power of 2).");
        raise_exception(env, EXCP0D_GPF);
    }

    // Reserved fields of TMP_SECS must be zero. If not, then GP(0)
    is_reserved_zero(tmp_secs_host->reserved1,  sizeof(((secs_t*)0)->reserved1), env); 
    is_reserved_zero(tmp_secs_host->reserved2, sizeof(((secs_t*)0)->reserved2), env); 
    is_reserved_zero(tmp_secs_host->reserved3, sizeof(((secs_t*)0)->reserved3), env); 
    is_reserved_zero(tmp_secs_host->eid_reserved.reserved,
                     sizeof(((secs_t*)0)->eid_reserved.reserved), env); 

    // TODO : SECS does not have any unsupported attributes
    // XXX: Where to set CR_SGX_ATTRIBUTES_MASK and the value?
    
    // Initialize MRENCLAVE field, isvsvn, and isvProdId
    sha256init(tmp_secs_host->mrEnclave); 

    tmp_secs_host->isvsvn = 0; 
    tmp_secs_host->isvprodID = 0; 

    // Initialize enclave's MRENCLAVE update counter
    tmp_secs_host->mrEnclaveUpdateCounter = 0; 

    // Update MRENCLAVE of SECS
    memset(&tmpUpdateField[0], 0, 64);
    memcpy(&tmpUpdateField[0], &hash_ecreate, sizeof(uint64_t));
    memcpy(&tmpUpdateField[8], &tmp_secs_host->ssaFrameSize, sizeof(uint32_t)); 
    memcpy(&tmpUpdateField[12], &tmp_secs_host->size, sizeof(uint64_t)); 
    memset(&tmpUpdateField[20], 0, 44);
    
    // Update MRENCLAVE hash value
    sha256update((unsigned char *)tmpUpdateField, tmp_secs_host->mrEnclave); 

    // Increase enclave's MRENCLAVE update counter
    tmp_secs_host->mrEnclaveUpdateCounter++; 


    // Check MRENCLAVE after ECREATE 
    {
        char hash[64+1];
        uint64_t counter = tmp_secs_host->mrEnclaveUpdateCounter; 

        fmt_hash(tmp_secs_host->mrEnclave, hash); 

        sgx_dbg(info, "measurement: %.20s.., counter: %ld", hash, counter);
    }

    // Set SECS.EID : starts from 0
    tmp_secs_host->eid_reserved.eid_pad.eid = env->cregs.CR_NEXT_EID;
    LockedXAdd(&(env->cregs.CR_NEXT_EID), 1);

    // Update EPCM of EPC page
    set_epcm_entry(&epcm[index_secs], 1, 0, 0, 0, 0, PT_SECS, 0, 0);
#ifdef THREAD_PROTECTION
    epcm[index_secs].enclave_tcs = 0;
#endif
    
    cpu_stx_data(env, tmp_secs, tmp_secs_host, sizeof(secs_t));

#if PERF
    int64_t eid;
    eid = tmp_secs_host->eid_reserved.eid_pad.eid;
    qenclaves[eid].stat.ecreate_n++;
    qenclaves[eid].stat.encls_n++;
#endif

    free(tmp_secs_host);
    free(tmp_secinfo_reserved);
    sgx_dbg(trace, "ecreate finishes well");
}


// In EADD, security measruement (SECS.MRENCLAVE) is updated for every new
// added TCS/REG page.
// Measuring target includes: EADD string, page address offset,
// PAGEINFO.SECINFO.
static
void sgx_eadd(CPUX86State *env)
{
    // RBX: PAGEINFO(In, EA)
    // RCX: EPCPAGE(In, EA)

    pageinfo_t *pageInfo = (pageinfo_t *)env->regs[R_EBX];
    epc_t *destPage = (epc_t *)env->regs[R_ECX];

    //TEMP Vars
    epc_t *tmp_srcpge;
    secs_t *tmp_secs;
#ifdef THREAD_PROTECTION
    tcs_t *tmp_tcs;
#endif
    secinfo_t *tmp_secinfo;
    secinfo_t scratch_secinfo;
    void *tmp_linaddr;
    uint64_t tmp_enclaveoffset;
    uint64_t tmpUpdateField[8];
    secs_t *tmp_secs_host; 

    // If RBX is not 32 Byte aligned, then GP(0).
    if (!is_aligned(pageInfo, PAGEINFO_ALIGN_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                pageInfo, PAGEINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If RCX is not 4KByte aligned, then GP(0).
    if (!is_aligned(destPage, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                destPage, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If RCX does not resolve within an EPC, then GP(0).
    check_within_epc(destPage, env);

    // set temp variables
    tmp_srcpge  = cpu_load_pi_srcpge(env, pageInfo);
    tmp_secinfo = cpu_load_pi_secinfo(env, pageInfo);
    tmp_secs    = cpu_load_pi_secs(env, pageInfo);
    tmp_linaddr = cpu_load_pi_linaddr(env, pageInfo);
#ifdef THREAD_PROTECTION
    tmp_tcs     = cpu_load_pi_tcs(env, pageInfo);
#endif

    sgx_dbg(eadd, " pageinfo : %p, destPage : %p", pageInfo, destPage);
    sgx_dbg(eadd, " srcpge : %08lx", (uintptr_t)tmp_srcpge);
    sgx_dbg(eadd, " secinfo: %08lx", (uintptr_t)tmp_secinfo);
    sgx_dbg(eadd, " secs: %p", tmp_secs);
    sgx_dbg(trace, " linaddr: %08lx", (uintptr_t)tmp_linaddr);
#ifdef THREAD_PROTECTION
    sgx_dbg(trace, " tcs: %p", tmp_tcs);
#endif

    // If tmp_srcpge is not 4KByte aligned or tmp_secs is not aligned or
    // tmp_secinfo is not 64 Byte aligned or tmp_linaddr is not 4KByte aligned,
    // then GP(0).
    if (!is_aligned(tmp_srcpge, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_srcpge, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    if (!is_aligned(tmp_secs, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_secs, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    if (!is_aligned(tmp_secinfo, SECINFO_ALIGN_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_secinfo, SECINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    if (!is_aligned(tmp_linaddr, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_linaddr, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If tmp_secs does not resolve within an EPC, then GP(0).
    check_within_epc(tmp_secs, env);

    // Copy secinfo into scratch_secinfo
    cpu_load_obj(env, &scratch_secinfo, tmp_secinfo, sizeof(secinfo_t));

    // scratch_secinfo->flags reserved field check. If it is not zero, then GP(0)
    checkReservedBits((uint64_t *)&scratch_secinfo.flags, 0xF8L, env); 
    checkReservedBits((uint64_t *)&scratch_secinfo.flags, 0xFFFFFFFFFFFF0000L, env); 

    // tmp_secinfo reserved field check. If it is not zero, then GP(0).
    is_reserved_zero(scratch_secinfo.reserved,
                     sizeof(((secinfo_t *)0)->reserved), env);

    // check page_type of scratch_secinfo. If it is not PT_REG or PT_TCS,
    // then GP(0).
    if (!((scratch_secinfo.flags.page_type == PT_REG) ||
        (scratch_secinfo.flags.page_type == PT_TCS))) { 
        raise_exception(env, EXCP0D_GPF);
    }

    // EPC page concurrency check
    // TODO: if EPC in use than raise exception

    // if epcm[RCX].valid == 1, then GP(0).
    uint16_t index_page = epcm_search(destPage, env);
    //sgx_dbg(eadd, "index_page: %d, destPage: %p", index_page, destPage);
    epcm_valid_check(&epcm[index_page], env);

    // SECS concurrency check
    // TODO: if secs not available for eadd raise exception

    // if epcm[tmp_secs] = 0 or epcm[tmp_secs].PT != PT_SECS, then GP(0)
    uint16_t index_secs = epcm_search(tmp_secs, env); 

    epcm_invalid_check(&epcm[index_secs], env);
    epcm_page_type_check(&epcm[index_secs], PT_SECS, env);

    // copy
    sgx_dbg(trace, "destPage is %p, tmp_srcpge is %p\n", destPage, tmp_srcpge); 
    cpu_load_n_store(env, destPage, tmp_srcpge, PAGE_SIZE); //cch: changed from memcpy(destPage, tmp_srcpge, PAGE_SIZE);

    // Actual Page copy from source to destination - XXX- Copy the entire page
    // 1) PT_TCS - Copy the entire page
    // 2) PT_REGS - Copy the address

    tmp_secs_host = cpu_load_secs(env, tmp_secs);  
    tcs_t tcs; 
    // Flags check of scratch_secinfo for each page type.
    sgx_dbg(trace, "page_type is %d", scratch_secinfo.flags.page_type);
    switch(scratch_secinfo.flags.page_type) {
        case PT_TCS: {
            cpu_load_obj(env, &tcs, destPage, sizeof(tcs_t));
            //checkReservedBits((uint64_t *)&tcs.flags, 0xFFFFFFFFFFFFFFFEL, env);
            if (tcs.reserved1 != 0 || tcs.reserved2 !=0){ //cch: need to check reserved3 too
                raise_exception(env, EXCP0D_GPF);
            }
            if ((tmp_secs_host->attributes.mode64bit == 0)
                && (((tcs.fslimit & 0x0FFF) != 0x0FFF)
                || ((tcs.gslimit & 0x0FFF) != 0x0FFF))) { 
                raise_exception(env, EXCP0D_GPF);
            }
#ifdef THREAD_PROTECTION
            if(tmp_tcs != 0){
                sgx_dbg(trace, "tcs field is not 0 in adding TCS");
                raise_exception(env, EXCP0D_GPF);
            }
            tcs.tid = env->cregs.CR_NEXT_TID; 
            sgx_dbg(trace, "tcs tid assigned is %d", tcs.tid);
            LockedXAdd(&(env->cregs.CR_NEXT_TID), 1);
            cpu_stx_data(env, destPage, &tcs, sizeof(tcs_t)); //cch: for storing tid
#endif
            break;
        }
        case PT_REG: {
            if ((scratch_secinfo.flags.w == 1) &&
                (scratch_secinfo.flags.r == 0)) {
                raise_exception(env, EXCP0D_GPF);
            }
#ifdef THREAD_PROTECTION
            if(tmp_tcs != 0){
                uint16_t index_tcs = epcm_search(tmp_tcs, env);
                epcm_invalid_check(&epcm[index_tcs], env);
                epcm_page_type_check(&epcm[index_tcs], PT_TCS, env);
            }
#endif
            break;
        }
        default: // no use
            break;
    }

    // Check enclave offset within enclave linear address space
    if((tmp_linaddr < tmp_secs_host->baseAddr)
        || (tmp_linaddr >= (tmp_secs_host->baseAddr + tmp_secs_host->size))) 
        raise_exception(env, EXCP0D_GPF);

    // Check concurrency of measurement resource
    //TODO

    // Check if the enclave to which the page will be added is already init
    // TODO

    // For TCS pages, force EPCM.rwx to 0 and no debug access
    if (scratch_secinfo.flags.page_type == PT_TCS) {
        scratch_secinfo.flags.r = 0;
        scratch_secinfo.flags.w = 0;
        scratch_secinfo.flags.x = 0;
        tcs.flags.dbgoptin = 0; 
        tcs.cssa = 0;  
        sgx_dbg(trace, "current cssa is %d", tcs.cssa); 
        cpu_stx_data(env, destPage, &tcs, sizeof(tcs_t)); //cch: this is not in spec, yet is required to meet the consistency between between host_tmp_address and guest_real_address
    }

    //cch: the following does not seem to be in the spec, but from opensgx:w
    if (scratch_secinfo.flags.page_type == PT_REG) {
        scratch_secinfo.flags.r = 1;
    //sgx_dbg(info, "r:%d w:%d x:%d", scratch_secinfo.flags.r, scratch_secinfo.flags.w, scratch_secinfo.flags.x);
    }

    // Update MRENCLAVE hash value
    tmp_enclaveoffset = (uintptr_t)tmp_linaddr - tmp_secs_host->baseAddr;
    tmpUpdateField[0] = 0x0000000044444145;
    memcpy(&tmpUpdateField[1], &tmp_enclaveoffset, 8);
    memcpy(&tmpUpdateField[2], &scratch_secinfo, 48);
    sha256update((unsigned char *)tmpUpdateField, tmp_secs_host->mrEnclave);

    // INC enclave's MRENCLAVE update counter
    tmp_secs_host->mrEnclaveUpdateCounter++;


    // Check MRENCLAVE after EADD
    {
        char hash[64+1];
        uint64_t counter = tmp_secs_host->mrEnclaveUpdateCounter;

        fmt_hash(tmp_secs_host->mrEnclave, hash);

        sgx_dbg(info, "measurement: %.20s.., counter: %ld", hash, counter);
    }

    // Set epcm entry
    set_epcm_entry(&epcm[index_page], 1, scratch_secinfo.flags.r,
                   scratch_secinfo.flags.w, scratch_secinfo.flags.x, 0,
                   scratch_secinfo.flags.page_type, return_hostaddr(env, (uint64_t)tmp_secs),
                   (uintptr_t)tmp_linaddr); 
#ifdef THREAD_PROTECTION
    if(tmp_tcs != 0){ 
        epcm[index_page].enclave_tcs = return_hostaddr(env, (uint64_t)tmp_tcs);
        sgx_dbg(trace, "TCS: %lx TCS_HOST: %lx", tmp_tcs, return_hostaddr(env, tmp_tcs));
    }
    else{ //tmp_tcs == 0
        epcm[index_page].enclave_tcs = NULL;
        sgx_dbg(trace, "TCS: %lx", tmp_tcs);
    }
#endif

#if DEBUG
    sgx_dbg(trace, "INDEX : %d EPC addr: %"PRIx64" SECS: %lx SECS_HOST: %lx", index_page, epcm[index_page].enclave_addr, tmp_secs, return_hostaddr(env, tmp_secs));
#endif

    cpu_stx_data(env, tmp_secs, tmp_secs_host, sizeof(secs_t));

#if PERF
    int64_t eid;
    eid = tmp_secs_host->eid_reserved.eid_pad.eid;
    qenclaves[eid].stat.eadd_n++;
    qenclaves[eid].stat.encls_n++;
#endif

    free(tmp_secs_host);
#if DEBUG
  {
    target_ulong addr_to_check = tmp_srcpge;
    
    int i;
    int k;
    
    fprintf(stderr, "tmp_srcpage-------------------\n", addr_to_check);
    for (k = 0; k < 20; k++) {
        fprintf(stderr, "%p :", addr_to_check);
        for (i = 0; i < 20; i++) {
            fprintf(stderr, "%02X ", cpu_ldub_data(env, addr_to_check + i)); 
        }    
        fprintf(stderr, "\n");
        addr_to_check += 20;
    }
    
    addr_to_check = destPage;
    fprintf(stderr, "destPage-------------------\n", addr_to_check);
    for (k = 0; k < 20; k++) {
        fprintf(stderr, "%p :", addr_to_check);
        for (i = 0; i < 20; i++) {
            fprintf(stderr, "%02X ", cpu_ldub_data(env, addr_to_check + i)); 
        }    
        fprintf(stderr, "\n");
        addr_to_check += 20;
    }  
  }
#endif
    sgx_dbg(trace, "eadd finishes well");
}

static
bool verify_signature(sigstruct_t *sig, uint8_t *signature, uint8_t *modulus,
                      uint32_t exponent)
{
    int ret = 1;
    rsa_context rsa;
    unsigned char hash[HASH_SIZE];
    sigstruct_t tmp_sig;

    rsa_init(&rsa, RSA_PKCS_V15, 0);

    // set public key
    mpi_read_binary(&rsa.N, modulus, KEY_LENGTH);
    mpi_lset(&rsa.E, (int)exponent);

    rsa.len = (mpi_msb(&rsa.N) + 7) >> 3;

    // generate hash for signature
    memcpy(&tmp_sig, sig, sizeof(sigstruct_t));

    // TODO: check q1 = floor(signature^2 / modulus)
    //             q2 = floor((signature^3 / modulus) / modulus)

    memset(&tmp_sig.exponent, 0, sizeof(tmp_sig.exponent));
    memset(&tmp_sig.modulus, 0, sizeof(tmp_sig.modulus));
    memset(&tmp_sig.signature, 0, sizeof(tmp_sig.signature));
    memset(&tmp_sig.q1, 0, sizeof(tmp_sig.q1));
    memset(&tmp_sig.q2, 0, sizeof(tmp_sig.q2));

    size_t ilen = (size_t)sizeof(sigstruct_t);
    sha1((uint8_t *)&tmp_sig, ilen, hash);

    if ((ret = rsa_pkcs1_verify(&rsa, NULL, NULL, RSA_PUBLIC, POLARSSL_MD_SHA1,
                                HASH_SIZE, hash, signature)) != 0) {
        sgx_dbg(warn, "failed! rsa_pkcs1_verify returned -0x%0x", -ret );
        return false;
    }

    return true;
}

static
bool is_debuggable_enclave_hash(uint8_t hash[32])
{
    int i;
    for (i = 0; i < sizeof(hash); i ++)
        if (hash[i] != 0)
            return false;
    return true;
}

// In EINIT, security measurement (SECS.MRENCLAVE) is finialized with
// update counter (total measuring times).
// Then several security checks are performed, include:
// 1. Verify SIGSTRUCT.Signature with SIGSTRUCT.Modulus (public key)
//    Also, verify SIGSTRUCT.q1 & q2
// 2. Compare MRSIGNER (hashed SIGSTRUCT.Modulus)
//    If intel signed enclave, compare with CSR_INTELPUBKEYHASH
//    Else compare with EINITTOKEN.MRSIGNER
// 3. Check EINITTOKEN(first 192 bytes) MAC with launch key
// 4. Compare SECS.MRENCLAVE with both SIGSTRUCT.ENCLAVEHASH and
//    EINITTOKEN.MRENCLAVE
static
void sgx_einit(CPUX86State *env)
{
    // RBX: SIGSTRUCT(In, EA)
    // RCX: SECS(In, EA)
    // RDX: EINITTOKEN(In, EA)

    sigstruct_t *sig = (sigstruct_t *)env->regs[R_EBX];
    secs_t *secs = (secs_t *)env->regs[R_ECX];
    einittoken_t *token = (einittoken_t*)env->regs[R_EDX];

    // Check for Alignments (SIGSTRUCT, SECS and EINITTOKEN)
    if (!is_aligned(sig, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                sig, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    if (!is_aligned(secs, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                secs, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    if (!is_aligned(token, EINITTOKEN_ALIGN_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                token, EINITTOKEN_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // Check if SECS is inside EPC
    check_within_epc(secs, env);

    // TEMP vars
    sigstruct_t tmp_sig;
    einittoken_t tmp_token;
    uint8_t tmp_mrEnclave[32];
    uint8_t tmp_mrSigner[32];
    attributes_t intel_only_mask;
    uint8_t csr_intelPubkeyHash[32];
    secs_t *tmp_secs; 
    
    // set temp variables
    cpu_load_obj(env, &tmp_sig, sig, sizeof(sigstruct_t)); 
    cpu_load_obj(env, &tmp_token, token, sizeof(einittoken_t)); 
    tmp_secs = cpu_load_secs(env, secs); 

    memcpy(tmp_mrEnclave, tmp_secs->mrEnclave, sizeof(tmp_mrEnclave));
    memcpy(tmp_mrSigner, tmp_secs->mrSigner, sizeof(tmp_mrSigner));

    uint64_t mask_val = 0x0000000000000020;
    memcpy(&intel_only_mask, &mask_val, sizeof(attributes_t));
    memcpy(csr_intelPubkeyHash, &env->cregs.CSR_INTELPUBKEYHASH,
           sizeof(csr_intelPubkeyHash));

    // Verify SIGSTRUCT Header
    if (checkSigStructField(tmp_sig, env)) {
        sgx_msg(warn, "check sigstruct field fail");
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_INVALID_SIG_STRUCT;
        goto _EXIT;
    }

    // Verify signature using embedded public key, q1, and q2.
    // Save upper 352 bytes of the PKCS1.5 encoded message into the
    // TMP_SIG_PADDING

    // Open “Event Window” Check for Interrupts.
    // Check for interrupts
    if (env->nmi_pending) {
        sgx_msg(warn, "pending check fail");
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_UNMASKED_EVENT;
        goto _EXIT;
    }

    // Caculate finalized version of MRENCLAVE
    uint64_t update_counter = tmp_secs->mrEnclaveUpdateCounter * 512;
    //sha256update((unsigned char *)&update_counter, 8, tmp_mrEnclave);
    sha256final(tmp_mrEnclave, update_counter); //cch: need to check later

    // Verify signature
    if (!verify_signature(&tmp_sig, tmp_sig.signature, tmp_sig.modulus, tmp_sig.exponent)) { 
        sgx_msg(warn, "signature verify fail");
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_INVALID_SIGNATURE;
        goto _EXIT;
    }

    // XXX : q1, q2 check will not considered
    // TODO : Set TMP_SIG_PADDING

    // Make sure no other SGX instruction is modifying SECS
    // TODO : implement checkSECSModification()
    if (checkSECSModification()) {
        sgx_msg(warn, "SECS modified");
        goto _EXIT;
    }

    // if epcm[tmp_secs] = 0 or epcm[tmp_secs].PT != PT_SECS, then GP(0)
    uint16_t index_secs = epcm_search(secs, env);
    epcm_invalid_check(&epcm[index_secs], env);
    epcm_page_type_check(&epcm[index_secs], PT_SECS, env);

    // TODO : Make sure no other instruction is accessing MRENCLAVE or ATTRIBUTES.INIT

    // Verify MRENCLAVE from SIGSTRUCT
#if DEBUG
    {
        unsigned char hash_measured[32];
        memcpy(hash_measured, tmp_mrEnclave, 32);
        sgx_msg(info, "Expected enclave measurement:--------testtest");
        int k;
		for (k = 0; k < 32; k++)
            fprintf(stderr, "%02X", (uint8_t)hash_measured[k]);
        fprintf(stderr, "\n");
    }
#endif

    bool is_debugging = is_debuggable_enclave_hash(tmp_sig.enclaveHash);

    if (!is_debugging && memcmp(tmp_sig.enclaveHash, tmp_mrEnclave, sizeof(tmp_mrEnclave)) != 0) {
        sgx_msg(warn, "enclavehash verification fail");
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_INVALID_MEASUREMENT;
        goto _EXIT;
    }

    // Set TMP_MRSIGNER
    sha256((unsigned char *)tmp_sig.modulus, KEY_LENGTH, tmp_mrSigner, 0);

    // When intel_only attributes are set, sigstruct must be signed using the Intel key
    attributes_t intel_attr = attr_mask(&tmp_secs->attributes, &intel_only_mask);
    attributes_t *zero_attr = (attributes_t *)calloc(1, sizeof(attributes_t));
    if ((memcmp(&intel_attr, zero_attr, sizeof(attributes_t)) != 0) &&
        (memcmp(tmp_mrSigner, csr_intelPubkeyHash, sizeof(tmp_mrSigner)) != 0)) {
        sgx_msg(warn, "intel only mask check fail");
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_INVALID_ATTRIBUTE;
        goto _EXIT;
    }
    free(zero_attr);

    // Verify Sigstruct.attributes requirements are met
    attributes_t secs_attr = attr_mask(&tmp_secs->attributes, &tmp_sig.attributeMask);
    attributes_t sig_attr = attr_mask(&tmp_sig.attributes, &tmp_sig.attributeMask);
    if (memcmp(&secs_attr, &sig_attr, sizeof(attributes_t)) != 0) {
        sgx_msg(warn, "attribute check1 fail");
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_INVALID_ATTRIBUTE;
        goto _EXIT;
    }

    // If EINITTOKEN.valid[0] is 0, verify the enclave is signed by Intel
    if (!is_debugging && (tmp_token.valid & 0x1) == 0) {
        if (memcmp(tmp_mrSigner, csr_intelPubkeyHash, 32) != 0) {
            sgx_msg(warn, "mrSigner fail");
            env->eflags |= CC_Z;
            env->regs[R_EAX] = ERR_SGX_INVALID_EINIT_TOKEN;
            goto _EXIT;
        }
        goto _COMMIT;
    }

    // Debug launch enclave cannot launch production enclaves
    if ((tmp_token.maskedAttributesLE.debug == 1) &&
        (tmp_secs->attributes.debug == 0)) {
        sgx_msg(warn, "debug check fail");
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_INVALID_EINIT_TOKEN;
        goto _EXIT;
    }

    // Check reserve space in EINITtoken includes reserved regions, upper bits in valid field
    is_reserved_zero(tmp_token.reserved1,
                     sizeof(((einittoken_t *)0)->reserved1), env);
    is_reserved_zero(tmp_token.reserved2,
                     sizeof(((einittoken_t *)0)->reserved2), env);
    is_reserved_zero(tmp_token.reserved3,
                     sizeof(((einittoken_t *)0)->reserved3), env);
    is_reserved_zero(tmp_token.reserved4,
                     sizeof(((einittoken_t *)0)->reserved4), env);

    checkReservedBits((uint64_t *)&tmp_token.valid, 0xFFFFFFFFFFFFFFFEL, env);

    // EINIT token must be <= CR_CPUSVN
    if (memcmp(tmp_token.cpuSvnLE, env->cregs.CR_CPUSVN, 16) > 0) {
        sgx_msg(warn, "cpuSVN check fail");
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_INVALID_CPUSVN;
        goto _EXIT;
    }

    // Derive launch key used to calculate EINITTOKEN.MAC
    uint8_t *pkcs1_5_padding = alloc_pkcs1_5_padding();

// (ref. r2 p85)
/*
    {
        sgx_msg(info, "check pkcs padding");
        int j;
        for (j = 351; j >= 0; j--)
            printf("%02x", pkcs1_5_padding[j]);
        printf("\n");
    }
*/

    keydep_t tmp_keydep;
    tmp_keydep.keyname = LAUNCH_KEY;
    tmp_keydep.isvprodID = tmp_token.isvprodIDLE;
    tmp_keydep.isvsvn = tmp_token.isvsvnLE;
    memcpy(tmp_keydep.ownerEpoch,      env->cregs.CSR_SGX_OWNEREPOCH, 16);
    memcpy(&tmp_keydep.attributes,     &tmp_token.maskedAttributesLE, 16);
    memset(&tmp_keydep.attributesMask, 0,                             16);
    memset(tmp_keydep.mrEnclave,       0,                             32);
    memset(tmp_keydep.mrSigner,        0,                             32);
    memcpy(tmp_keydep.keyid,           tmp_token.keyid,               32);
    memcpy(tmp_keydep.seal_key_fuses,  env->cregs.CR_SEAL_FUSES,      16);
    memcpy(tmp_keydep.cpusvn,          tmp_token.cpuSvnLE,            16);
    memcpy(&tmp_keydep.miscselect,     &tmp_token.maskedmiscSelectLE,  4);
    memset(&tmp_keydep.miscmask,       0,                              4);
    memcpy(tmp_keydep.padding,         pkcs1_5_padding,              352);

    // Calculate derived key
    uint8_t launch_key[16];
    sgx_derivekey(&tmp_keydep, (unsigned char *)launch_key);

    // Verify EINITTOKEN was generated using this CPU's launch key and that
    // it has not been modified since issuing by the launch enclave.
    // Only 192 bytes of EINITTOKEN are CMACed.
    uint8_t tmp_cmac[16];

    aes_cmac128_context ctx;
    aes_cmac128_starts(&ctx, launch_key);
    aes_cmac128_update(&ctx, (uint8_t *)&tmp_token, 192);
    aes_cmac128_final(&ctx, tmp_cmac);

#if DEBUG
    {
        sgx_msg(info, "Expected launch key:");
        int l;
		for (l = 0; l < 16; l++)
            fprintf(stderr, "%02X", launch_key[l]);
        fprintf(stderr, "\n");
    }
#endif

#if 0
    // Expected einittoken mac
	{
        char token_mac[16+1];
        fmt_hash(tmp_cmac, token_mac);
        sgx_dbg(info, "token mac: %.20s", token_mac);
    }
#endif

// XXX: Bypass
#if 0
    if (!is_debugging) {
        if (memcmp(tmp_token.mac, tmp_cmac, 16)) {
            sgx_dbg(err, "MAC value check fail");
            env->eflags |= CC_Z;
            env->regs[R_EAX] = ERR_SGX_INVALID_EINIT_TOKEN;
            goto _EXIT;
        }

        // Verify EINITTOKEN(RDX) is for this enclave
        if (memcmp(tmp_token.mrEnclave, tmp_mrEnclave, 32)
            || memcmp(tmp_token.mrSigner, tmp_mrSigner, 32)) {
            sgx_msg(warn, "enclave & sealing identity check fail");
            env->eflags |= CC_Z;
            env->regs[R_EAX] = ERR_SGX_INVALID_MEASUREMENT;
            goto _EXIT;
        }

        // Verify ATTRIBUTES in EINITTOKEN are the same as the enclave's
        if (memcmp(&tmp_token.attributes, &secs->attributes, sizeof(attributes_t))) {
            sgx_msg(warn, "attribute check2 fail");
            env->eflags |= CC_Z;
            // err in ref : ERR_SGX_INVALID_EINIT_ATTRIBUTES -> ERR_SGX_INVALID_ATTRIBUTE
            env->regs[R_EAX] = ERR_SGX_INVALID_ATTRIBUTE;
            goto _EXIT;
        }
    }
#endif

    einit_Success = true;

_COMMIT:
    // Commit changes to the SECS
    memcpy(&tmp_secs->mrEnclave, tmp_mrEnclave, sizeof(tmp_mrEnclave));

    // MRSIGNER stores a SHA256 in little endian implemented natively on x86
    memcpy(&tmp_secs->mrSigner, tmp_mrSigner, sizeof(tmp_mrSigner));
    memcpy(&tmp_secs->isvprodID, &tmp_sig.isvProdID, sizeof(uint16_t));
    memcpy(&tmp_secs->isvsvn, &tmp_sig.isvSvn, sizeof(uint16_t));
    // TODO : mark the SECS as initialized -> By setting padding fields
    // TODO padding??
    // XXX : how to make padding for secs->padding with sigstruct??
    // secs->eid_reserved.eid_pad.padding

    // Set RAX and ZF for success
    env->eflags &= ~CC_Z;        // ZF = 6
    env->regs[R_EAX] = 0;

    markEnclave(tmp_secs->eid_reserved.eid_pad.eid);

    cpu_stx_data(env, secs, tmp_secs, sizeof(secs_t));
   
_EXIT:
    /* clear flags : CF, PF, AF, OF, SF */
    env->eflags &= ~(CC_C | CC_P | CC_A | CC_S | CC_O);
#if PERF
    int64_t eid;
    eid = tmp_secs->eid_reserved.eid_pad.eid;
    qenclaves[eid].stat.einit_n++;
    qenclaves[eid].stat.encls_n++;
#endif

    free(tmp_secs);
}

static
void sgx_eldb(CPUX86State *env)
{
    //EAX: eldb/eldu(In)
    //RBX: pageinfo addr(In)
    //RCX: Epc page addr(In)
    //RDX: VA  slot addr(In)
    //EAX: Error code(Out)
    sgx_dbg(trace, "eldb starts well");
    pageinfo_t *tmp_pageinfo_host;
    uint64_t *tmp_srcpge; 
    uint64_t *tmp_srcpge_host;
    unsigned char ciphertext[4096];
    unsigned char page_to_load[4096];
    secs_t *tmp_secs;
    secs_t *tmp_secs_host;
#ifdef THREAD_PROTECTION
    tcs_t *tmp_tcs = NULL;
    tcs_t *tmp_tcs_host = NULL;
    uint64_t tcs_index;
#endif
    pcmd_t *tmp_pcmd;
    pcmd_t *tmp_pcmd_host;
    mac_header_t tmp_header;
    unsigned char iv[] = {0,0,0,0,0,0,0,0,0,0,0,0}; //cch: IV is 12 bytes
    uint64_t tmp_ver;
    uint64_t tmp_mac[2];
    uint64_t epc_index, va_index, secs_index;

    if(!is_aligned(env->regs[R_EBX], 32) || !is_aligned(env->regs[R_ECX], PAGE_SIZE)) {
        raise_exception(env, EXCP0D_GPF);
    }

    check_within_epc((void *)env->regs[R_ECX], env);

    if(!is_aligned(env->regs[R_EDX], 8)) {
        raise_exception(env, EXCP0D_GPF);
    }

    check_within_epc((void *)env->regs[R_EDX], env);

    tmp_pageinfo_host = cpu_ldx_data(env, (env->regs[R_EBX]), sizeof(pageinfo_t));
    tmp_srcpge = tmp_pageinfo_host->srcpge;
    tmp_srcpge_host = cpu_ldx_data(env, tmp_srcpge, PAGE_SIZE);
    tmp_secs = tmp_pageinfo_host->secs;
    tmp_secs_host = cpu_load_secs(env, tmp_secs);
#ifdef THREAD_PROTECTION
    tmp_tcs = tmp_pageinfo_host->tcs;
    if (tmp_tcs != NULL){
        tmp_tcs_host = cpu_load_tcs(env, tmp_tcs);
    }
#endif
    tmp_pcmd = tmp_pageinfo_host->pcmd;
    tmp_pcmd_host = cpu_ldx_data(env, tmp_pcmd, sizeof(pcmd_t));

    if(!is_aligned(tmp_pcmd, sizeof(pcmd_t)) || !is_aligned(tmp_srcpge, PAGE_SIZE)) {
        raise_exception(env, EXCP0D_GPF);
    }

    //TODO: (* Check concurrency of EPC and VASLOT by other SGX instructions *)

    epc_index = epcm_search((void *)env->regs[R_ECX], env);
    va_index = epcm_search((void *)env->regs[R_EDX], env);
    if(epcm[epc_index].valid == 1){
        raise_exception(env, EXCP0D_GPF);
    }

    if(epcm[va_index].valid == 0 || epcm[va_index].page_type != PT_VA) {
        raise_exception(env, EXCP0D_GPF);
    }

    memset(&tmp_header, 0 , sizeof(tmp_header));
    tmp_header.secinfo.flags.page_type = tmp_pcmd_host->secinfo.flags.page_type;
    tmp_header.secinfo.flags.r = tmp_pcmd_host->secinfo.flags.r;
    tmp_header.secinfo.flags.w = tmp_pcmd_host->secinfo.flags.w;
    tmp_header.secinfo.flags.x = tmp_pcmd_host->secinfo.flags.x;
    //cch: where is copying reserved field?
    tmp_header.linaddr = tmp_pageinfo_host->linaddr;

    if(tmp_header.secinfo.flags.page_type == PT_REG || 
       tmp_header.secinfo.flags.page_type == PT_TCS) {
        if(!is_aligned(tmp_secs, PAGE_SIZE)) {
            raise_exception(env, EXCP0D_GPF);
        }
        check_within_epc((void *)tmp_secs, env);
        //TODO: Other instructions modifiying SECS
        secs_index = epcm_search(tmp_secs, env);
        if(epcm[secs_index].valid == 0 || epcm[secs_index].page_type != PT_SECS) { //cch: opensgx typo
            raise_exception(env, EXCP0D_GPF);
        }
    }
    else if(tmp_header.secinfo.flags.page_type == PT_SECS ||
            tmp_header.secinfo.flags.page_type == PT_VA) {
        if(tmp_secs != 0)
            raise_exception(env, EXCP0D_GPF);
    }
    else {
        raise_exception(env, EXCP0D_GPF);
    }
    if (tmp_header.secinfo.flags.page_type == PT_REG ||
        tmp_header.secinfo.flags.page_type == PT_TCS ||
        tmp_header.secinfo.flags.page_type == PT_TRIM) { 
        tmp_header.eid = tmp_secs_host->eid_reserved.eid_pad.eid;
    }
    else {
        tmp_header.eid = 0;
    }
#ifdef THREAD_PROTECTION
    if(tmp_header.secinfo.flags.page_type == PT_REG){
        if(tmp_tcs != NULL){
            if(!is_aligned(tmp_tcs, PAGE_SIZE)) {
                sgx_dbg(trace, "passed tcs field is not page aligned");
                raise_exception(env, EXCP0D_GPF);
            }
            check_within_epc((void *)tmp_tcs, env);
            tcs_index = epcm_search(tmp_tcs, env);
            if(epcm[tcs_index].valid == 0 || epcm[tcs_index].page_type != PT_TCS) { 
                sgx_dbg(trace, "passed tcs field is not valid nor PT_TCS");
                sgx_dbg(trace, "tmp_tcs is %p, epcm.valid: epcm.page_type%d, ", tmp_tcs, epcm[tcs_index].valid, epcm[tcs_index].page_type);
                raise_exception(env, EXCP0D_GPF);
            }
        }
    }
    else if(tmp_header.secinfo.flags.page_type == PT_SECS ||
            tmp_header.secinfo.flags.page_type == PT_TCS ||
            tmp_header.secinfo.flags.page_type == PT_VA) {
        if(tmp_tcs != 0){
            sgx_dbg(trace, "TCS field is not NULL in (PT_SECS, PT_TCS, PT_VA) loading");
            raise_exception(env, EXCP0D_GPF);
        }
    }
    if (tmp_header.secinfo.flags.page_type == PT_REG ||
        tmp_header.secinfo.flags.page_type == PT_TRIM) { 
        if(tmp_tcs != NULL && tmp_tcs_host != NULL){
            tmp_header.tid = tmp_tcs_host->tid;
        }
        else{ //shared page
            tmp_header.tid = 0; 
        }
    }    
    else {
        tmp_header.tid = 0; 
    }  
#endif
    memcpy(ciphertext, tmp_srcpge_host, PAGE_SIZE);
    tmp_ver = cpu_ldq_data(env, (env->regs[R_EDX]));
    memcpy(iv, &tmp_ver, 8); //cch: 32bit left-shift VA value before passing it to the IV

    decrypt_epc(ciphertext, PAGE_SIZE, (unsigned char *)&tmp_header, sizeof(mac_header_t),
                (unsigned char *)tmp_pcmd_host->mac, gcm_key, iv, page_to_load); 

    /* cch: decrypt_epc has MAC comparing logic
    if(!memcmp(tmp_mac, tmp_pcmd_host->mac, 16)) {
        sgx_dbg(trace, "The generated MAC does not match with the original MAC");
        env->regs[R_EAX] = ERR_SGX_MAC_COMPARE_FAIL;
        goto ERROR_EXIT;
    }
    */

    //cch: I think the follwing in SPEC is non-sense, thus should be deleted
    /*
    if(env->regs[R_EDX] != 0) { //XXX ? 
        raise_exception(env, EXCP0D_GPF);
    }
    else {
        env->regs[R_EDX] = tmp_ver;
    }
    */
    //cch: I think the above should be changed below to free VA_slot
    if(tmp_ver == 0){
        sgx_dbg(trace, "VA slot is empty");
        raise_exception(env, EXCP0D_GPF);
    }
    else{
        uint64_t VA_slot = 0;
        cpu_stq_data(env, (env->regs[R_EDX]), VA_slot);
    }

    epcm[epc_index].page_type = tmp_header.secinfo.flags.page_type;
    epcm[epc_index].read    = tmp_header.secinfo.flags.r;
    epcm[epc_index].write   = tmp_header.secinfo.flags.w;
    epcm[epc_index].execute = tmp_header.secinfo.flags.x;
    epcm[epc_index].enclave_addr = tmp_header.linaddr;
    if(tmp_secs != NULL){
        epcm[epc_index].enclave_secs = return_hostaddr(env, tmp_secs);  //cch: this is not in SPEC, but indeed necessary
    }
    else{
        epcm[epc_index].enclave_secs = 0;  //cch: this is not in SPEC, but indeed necessary
    }
#ifdef THREAD_PROTECTION
    if (tmp_tcs != NULL){
        epcm[epc_index].enclave_tcs = return_hostaddr(env, tmp_tcs); 
    }
    else{
        epcm[epc_index].enclave_tcs = NULL; 
    }
#endif 

    if(env->regs[R_EAX] == 0x07 && (tmp_header.secinfo.flags.page_type != PT_SECS || 
                                    tmp_header.secinfo.flags.page_type != PT_VA  )) 
        epcm[epc_index].blocked = 1;
    else
        epcm[epc_index].blocked = 0;

    epcm[epc_index].valid = 1;
    env->regs[R_EAX] = 0;
    env->eflags &= ~(CC_Z);

    ERROR_EXIT:
        env->eflags &= ~(CC_C | CC_P | CC_A | CC_O | CC_S);

    cpu_stx_data(env, env->regs[R_ECX], page_to_load, EPC_SIZE);
#ifdef THREAD_PROTECTION
    if(tmp_tcs_host != NULL){
        free(tmp_tcs_host);
    }
#endif
    free(tmp_secs_host);
    free(tmp_pageinfo_host);    
    free(tmp_srcpge_host);
    free(tmp_pcmd_host);
 
    sgx_dbg(trace, "eldb finishes well");
}


static void sgx_eremove(CPUX86State *env)
{
    epc_t *tmp_epcpage = (epc_t *)env->regs[R_ECX];

    // If RCX is not 4KB Aligned, then GP(0)
    if (!is_aligned((void *)tmp_epcpage, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                (void *)tmp_epcpage, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If RCX does not resolve within an EPC, then GP(0)
    check_within_epc((void *)tmp_epcpage, env);

    // TODO : Check the EPC page for concurrency

    // If RCX is already unused, nothing to do
    uint8_t index_page = epcm_search((void *)tmp_epcpage, env);

    if ((epcm[index_page].valid == 0) || 
        (epcm[index_page].page_type == PT_TRIM && epcm[index_page].modified == 0)) {
        goto _DONE;
    }

    if (epcm[index_page].page_type == PT_VA) {
        epcm[index_page].valid = 0;
        goto _DONE;
    }

    if (epcm[index_page].page_type == PT_SECS) {
        // TODO : RCX has an EPC page associated with it check
        epcm[index_page].valid = 0;
        goto _DONE;
    }

    // secs_t *tmp_secs = get_secs_address(&epcm[index_page]);
    // TODO : If other threads active using SECS

    //cch: this is not in the spec, but necessary for REG_PAGE or TCS_PAGE
    epcm[index_page].valid = 0;

_DONE:
    env->regs[R_EAX] = 0;
    env->eflags &= ~CC_Z;

_ERROR_EXIT:
    // clear flags : CF, PF, AF, OF, SF
    env->eflags &= ~(CC_C | CC_P | CC_A | CC_O | CC_S);
    sgx_dbg(trace, "eremove finishes well");
}


// In EEXTEND, security measurement (SECS.MRENCLAVE) is updated for every
// page chunk (256 Bytes).
// There are two measurement steps:
// Step 1. Measuring EEXTEND string, page chunk offset.
// Step 2. Measuring the page chunk memory (4 times, 64 Bytes each).
static
void sgx_eextend(CPUX86State *env)
{
    // RCX: EPCPAGE(In, EA)

    uint64_t *target_addr = (uint64_t *)env->regs[R_ECX];
    secs_t *tmp_secs;
    uint64_t tmp_enclaveoffset;
    uint64_t tmpUpdateField[8];
    secs_t *tmp_secs_host; 
    uint64_t target_addr_host[32];

    // If RCX is not 256 Byte aligned, then GP(0)
    if (!is_aligned(target_addr, MEASUREMENT_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                target_addr, MEASUREMENT_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If RCX does not resolve within an EPC, then GP(0)
    check_within_epc(target_addr, env);

    // Check other instructions accessing EPCM
    uint16_t index_page = epcm_search(target_addr, env);
    epcm_invalid_check(&epcm[index_page], env);

    // Page Type check of RCX
    if ((epcm[index_page].page_type != PT_REG) &&
        (epcm[index_page].page_type != PT_TCS)) {
        raise_exception(env, EXCP0D_GPF);
    }

    // Set tmp_secs
    tmp_secs = get_secs_address(&epcm[index_page]);
    tmp_secs_host = load_secs(tmp_secs); 

    // check other instructions are accessing MRENCLAVE or ATTRIBUTES.INIT
    // TODO

    // Calculate enclave offset. 
    tmp_enclaveoffset = epcm[index_page].enclave_addr - tmp_secs_host->baseAddr; 
    tmp_enclaveoffset = tmp_enclaveoffset + ((uint64_t)target_addr & 0x0FFF); 
    sgx_dbg(eextend, "enclave addr is %p, baseaddr is %p, target_addr is %p, enclave offset is %p", epcm[index_page].enclave_addr, tmp_secs_host->baseAddr, target_addr, tmp_enclaveoffset);  

    // Update MRENCLAVE of SECS
    tmpUpdateField[0] = 0x00444E4554584545;
    memcpy(&tmpUpdateField[1], &tmp_enclaveoffset, 8);
    memset(&tmpUpdateField[2], 0, 48);

    // Update MRENCLAVE hash value
    sha256update((unsigned char *)tmpUpdateField, tmp_secs_host->mrEnclave);

    // Increase MRENCLAVE update counter
    tmp_secs_host->mrEnclaveUpdateCounter++;


    // Check MRENCLAVE for EEXTEND instruction
    {
        char hash[64+1];
        uint64_t counter = tmp_secs_host->mrEnclaveUpdateCounter;

        fmt_hash(tmp_secs_host->mrEnclave, hash);

        sgx_dbg(eextend, "measurement: %.20s.., counter: %ld", hash, counter);
    }


    cpu_load_obj(env, target_addr_host, target_addr, 256); 

    // Add 256 bytes to MRENCLAVE, 64 byte at a time
    sha256update((unsigned char *)(&target_addr_host[0]), tmp_secs_host->mrEnclave); 
    sha256update((unsigned char *)(&target_addr_host[8]), tmp_secs_host->mrEnclave);
    sha256update((unsigned char *)(&target_addr_host[16]), tmp_secs_host->mrEnclave);
    sha256update((unsigned char *)(&target_addr_host[24]), tmp_secs_host->mrEnclave);

    // Increase enclaves's MRENCLAVE update counter by 4
    tmp_secs_host->mrEnclaveUpdateCounter += 4;


    // Check MRENCLAVE for page chunk
    {
        char hash[64+1];
        uint64_t counter = tmp_secs_host->mrEnclaveUpdateCounter;

        fmt_hash(tmp_secs_host->mrEnclave, hash);

        sgx_dbg(eextend, "measurement: %.20s.., counter: %ld", hash, counter);
    }

    stx_raw(tmp_secs, tmp_secs_host, sizeof(secs_t));

#if PERF
    int64_t eid;
    eid = tmp_secs_host->eid_reserved.eid_pad.eid;
    qenclaves[eid].stat.eextend_n++;
    qenclaves[eid].stat.encls_n++;
#endif

    free(tmp_secs_host);
}

// EAUG instruction
static
void sgx_eaug(CPUX86State *env)
{
    pageinfo_t *pageInfo = (pageinfo_t*)env->regs[R_EBX];    //spec says RBX is the address of a SECINFO, but it is a typo
    epc_t *destPage = (epc_t *)env->regs[R_ECX];
    epc_t *destPage_host; 

    //TEMP Vars
    epc_t *tmp_srcpge;
    secs_t *tmp_secs;
#ifdef THREAD_PROTECTION
    tcs_t *tmp_tcs;
#endif
    secs_t *tmp_secs_host; 
    secinfo_t *tmp_secinfo;
    void *tmp_linaddr;
    uint64_t eid;

    // If RBX is not 32 Byte aligned, then GP(0).
    if (!is_aligned(pageInfo, PAGEINFO_ALIGN_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                pageInfo, PAGEINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If RCX is not 4KByte aligned, then GP(0).
    if (!is_aligned(destPage, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                destPage, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If RCX does not resolve within an EPC, then GP(0).
    check_within_epc(destPage, env);

    // set temp variables
    tmp_srcpge  = cpu_load_pi_srcpge(env, pageInfo);
    tmp_secs    = cpu_load_pi_secs(env, pageInfo);
    tmp_secinfo = cpu_load_pi_secinfo(env, pageInfo);
    tmp_linaddr = cpu_load_pi_linaddr(env, pageInfo);
#ifdef THREAD_PROTECTION
    tmp_tcs     = cpu_load_pi_tcs(env, pageInfo);
#endif

    tmp_secs_host = cpu_load_secs(env, tmp_secs); 
    destPage_host = cpu_ldx_data(env, destPage, sizeof(epc_t));

    // If tmp_secs is not 4KByte aligned or tmp_linaddr is not 4KByte aligned,
    // then GP(0).
    if (!is_aligned(tmp_secs, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_secs, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    if (!is_aligned(tmp_linaddr, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_linaddr, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If srcpge and secinfo of pageInfo is non-zero, then GP(0)
    if (tmp_srcpge != 0 || tmp_secinfo != 0) {
        raise_exception(env, EXCP0D_GPF);
    }

    // If tmp_secs does not resolve within an EPC, then GP(0).
    check_within_epc(tmp_secs, env);

    // EPC page concurrency check
    // TODO: if EPC in use than raise exception

    // if epcm[RCX].valid == 1, then GP(0).
    uint16_t index_page = epcm_search(destPage, env);
    epcm_valid_check(&epcm[index_page], env);

    // SECS concurrency check
    // TODO: if secs not available for eaug raise exception

    // if epcm[tmp_secs].valid = 0 or epcm[tmp_secs].PT != PT_SECS, then GP(0)
    uint16_t index_secs = epcm_search(tmp_secs, env);

    epcm_invalid_check(&epcm[index_secs], env);
    epcm_page_type_check(&epcm[index_secs], PT_SECS, env);

#ifdef THREAD_PROTECTION
    if(tmp_tcs != 0){
        uint16_t index_tcs = epcm_search(tmp_tcs, env);

        epcm_invalid_check(&epcm[index_tcs], env);
        epcm_page_type_check(&epcm[index_tcs], PT_TCS, env);
    }
#endif

    eid = tmp_secs_host->eid_reserved.eid_pad.eid;
    // check if enclave to which the page will be added is in the Initiallized state
    // TODO: the initialized state should belong to the enclave of our interest
    if (!checkEINIT(eid)) {
        raise_exception(env, EXCP0D_GPF);
    }

    // Check enclave offset within enclave linear address space
    if(((uintptr_t)tmp_linaddr < tmp_secs_host->baseAddr)
        || ((uintptr_t)tmp_linaddr >= (tmp_secs_host->baseAddr + tmp_secs_host->size))){
        sgx_dbg(err, "Enclave offset is not within the enclave linear address space");
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg(trace, "DEBUG EAUG baseaddr is %lX, endaddr is %lX", tmp_secs_host->baseAddr, (tmp_secs_host->baseAddr + tmp_secs_host->size));
    sgx_dbg(trace, "DEBUG linear addr is %p", (void *)tmp_linaddr);


    // clear the content of EPC page
    memset(destPage_host, 0, PAGE_SIZE); 
    cpu_stx_data(env, destPage, destPage_host, PAGE_SIZE); 

    // Set epcm entry
    set_epcm_entry(&epcm[index_page], 1,       //epcm_entry, valid,
                   1, 1, 0, 0,                 //read, write, execute, block,
                   PT_REG, return_hostaddr(env, (uint64_t)tmp_secs), //pt, secs,
                   (uintptr_t)tmp_linaddr);               //linaddr
#ifdef THREAD_PROTECTION
    if(tmp_tcs != 0){
        epcm[index_page].enclave_tcs = return_hostaddr(env, (uint64_t)tmp_tcs);
    }
    else{ //shared page
        epcm[index_page].enclave_tcs = NULL;
    }
#endif

    epcm[index_page].pending = 1;
    epcm[index_page].modified = 0;

#if PERF
    qenclaves[eid].stat.eaug_n++;
    qenclaves[eid].stat.encls_n++;
#endif
    free(tmp_secs_host);
    free(destPage_host);
    sgx_dbg(trace, "eaug finishes well");
}

static
void sgx_emodpr(CPUX86State *env)
{
    // RBX: Secinfo Addr(In)
    // RCX: Destination EPC Addr(In)
    // EAX: Error Code(out)
    uint64_t sec_index = 0; 
    uint64_t epc_index = 0; 

    secs_t   *tmp_secs;
    secinfo_t *scratch_secinfo;
    secinfo_t *tmp_secinfo; 
    tmp_secinfo = (secinfo_t *) env->regs[R_EBX]; 
    epc_t *destPage = (epc_t *) env->regs[R_ECX]; 
    
    sgx_dbg( trace, "emodpr called well");
    sgx_dbg( trace, "%p, %p\n", (void*)tmp_secinfo, destPage);
 
    if(!is_aligned(tmp_secinfo, SECINFO_ALIGN_SIZE)) {
        sgx_dbg( err, "Failed to check alignment: %p on %d bytes", tmp_secinfo, SECINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "emodpr SECINFO alignment well");

    if(!is_aligned(destPage, PAGE_SIZE)) {
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "emodpr EPC alignment well");

    check_linaddr_within_epc(destPage, env);
    sgx_dbg( trace, "check_linaddr_within_epc");

    scratch_secinfo = cpu_ldx_data( env, tmp_secinfo, sizeof(secinfo_t));

    // (* Check for mis-configured SECINFO flags*)
    is_reserved_zero(&(scratch_secinfo->reserved), sizeof(((secinfo_t *)0)->reserved), env);
    sgx_dbg( trace, "reserved zero check");

    if (!(scratch_secinfo->flags.r == 0 || scratch_secinfo->flags.w != 0)) {
        raise_exception(env, EXCP0D_GPF);
    }

    // TODO: Check concurrency with SGX1 or SGX2 instructions on the EPC page

    epc_index = epcm_linsearch((void *)destPage, env);
    epcm_entry_t *epcm_epc = &epcm[epc_index]; 

    if(epcm_epc->valid == 0) {
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "EPCM valid");

    // TODO: Check the EPC page for concurrency

    if( epcm_epc->pending != 0 || epcm_epc->modified != 0) {
        sgx_dbg( trace, "SGX page is not modifiable");
        env->eflags = 1;
        env->regs[R_EAX] = ERR_SGX_PAGE_NOT_MODIFIABLE;
        goto Done;
    }
    sgx_dbg( trace, "SGX page is modifiable");

    if( epcm_epc->page_type != PT_REG) {
        sgx_dbg( trace, "EPC page is not PT_REG");
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "EPC page is PT_REG");

    tmp_secs = get_secs_address(epcm_epc);
    //we don't have init field in secs.attributes..
    //TODO: if(tmp_secs.attributes.init == 0)
    //TODO: check concurrency with ETRACK

    sgx_dbg( trace, "EPCM permission : %d, %d, %d", epcm_epc->read, epcm_epc->write, epcm_epc->execute );
    epcm_epc->read &= scratch_secinfo->flags.r;
    epcm_epc->write &= scratch_secinfo->flags.w;
    epcm_epc->execute &= scratch_secinfo->flags.x;
    sgx_dbg( trace, "update EPCM permission : %d, %d, %d", epcm_epc->read, epcm_epc->write, epcm_epc->execute );

    env->eflags &= ~(CC_Z);
    env->regs[R_EAX] = 0;

    cpu_stx_data( env, tmp_secinfo, scratch_secinfo, sizeof(secinfo_t));
    sgx_dbg( trace, "after cpu_stx_data");

    free( scratch_secinfo); 

    // next instruction 
    env->cregs.CR_CURR_EIP = env->cregs.CR_NEXT_EIP;
    env->cregs.CR_ENC_INSN_RET = true; 

    Done:
        env->eflags &= ~(CC_C | CC_P | CC_A | CC_O | CC_S);
}

static
void sgx_eblock(CPUX86State *env)
{
    // RCX: EPC Addr(In, EA)
    // EAX: Error Code(Out)

    uint64_t *epc_addr = (uint64_t *)env->regs[R_ECX];
    uint16_t epcm_index = 0;
    uint64_t tmp_blkstate = 0;
    // Check if DS:RCX is not 4KByte Aligned
    if (!is_aligned(epc_addr, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                epc_addr, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }

    // If RCX does not resolve within an EPC, then GP(0).
    check_within_epc(epc_addr, env);

    // Clear ZF,CF,PF,AF,OF,SF;
    env->eflags &= ~(CC_Z | CC_C | CC_P | CC_A | CC_O | CC_S);

    // TODO - Check concurrency with other instructions

    epcm_index = epcm_search(epc_addr, env);
    if(epcm[epcm_index].valid == 0) {
        env->eflags |= CC_Z;
        env->regs[R_EAX] = ERR_SGX_PG_INVLD;
	goto Done; 
    }

    if((epcm[epcm_index].page_type != PT_REG) && (epcm[epcm_index].page_type != PT_TCS) &&
       (epcm[epcm_index].page_type != PT_TRIM)) {
        env->eflags &= CC_C;
        if(epcm[epcm_index].page_type == PT_SECS) {
            env->regs[R_EAX] = ERR_SGX_PG_IS_SECS;
        }
        else {
            env->regs[R_EAX] = ERR_SGX_NOTBLOCKABLE;
        }
        goto Done;
    }
    
    // (* Check if the page is already blocked and report blocked state *)
    tmp_blkstate = epcm[epcm_index].blocked;

    // (* at this point, the page must be valid and PT_TCS or PT_REG or PT_TRIM*)
    if(tmp_blkstate == 1) {
        env->eflags |= CC_C;
        env->regs[R_EAX] = ERR_SGX_BLKSTATE;
    }
    else {
        epcm[epcm_index].blocked = 1;
    }

Done: 
    sgx_dbg(trace, "eblock finishes well");
    return;
}

/*
1. Enclave signals OS that a particular page is no longer in use.
2. OS calls EMODT on the page, requesting that the page’s type be changed to PT_TRIM.
a. SECS and VA pages cannot be trimmed in this way, so the initial type of the page must be PT_REG or
PT_TCS
b. EMODT may only be called on VALID pages
3. OS performs an ETRACK instruction to remove the TLB addresses from all the processors
4. Enclave issues an EACCEPT instruction.
5. The OS may now permanently remove it (by calling EREMOVE).
*/
static
void sgx_emodt(CPUX86State *env)
{
    // RBX: SECINFO addr(In, EA)
    // RCX: EPC Addr(In, EA)
    // EAX: Error Code(Out)
    uint64_t sec_index = 0;
    uint64_t epc_index = 0; 

    secs_t    *tmp_secs;
    secs_t    *tmp_secs_host;
    secinfo_t *scratch_secinfo;
    secinfo_t *tmp_secinfo = (secinfo_t *) env->regs[R_EBX];
    epc_t     *target_addr = (epc_t *)     env->regs[R_ECX];
    uint16_t epcm_index = 0;

    sgx_dbg( trace, "emodt called well" );
    sgx_dbg( trace, "%p, %p", (void*)tmp_secinfo, target_addr);

    // If RBX is not 64 Byte aligned, then GP(0).
    if (!is_aligned(tmp_secinfo, SECINFO_ALIGN_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                tmp_secinfo, SECINFO_ALIGN_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "emodt SECINFO alignment well");

    // If RCX is not 4 KByte aligned, then GP(0).
    if (!is_aligned(target_addr, PAGE_SIZE)) {
        sgx_dbg(err, "Failed to check alignment: %p on %d bytes",
                target_addr, PAGE_SIZE);
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "emodt EPC alignment well");

    // If RCX does not resolve within an EPC, then GP(0).
    check_linaddr_within_epc(target_addr, env);
    sgx_dbg( trace, "check_linaddr_within_epc");

    scratch_secinfo = cpu_ldx_data( env, tmp_secinfo, sizeof(secinfo_t));

    // (* Check for mis-configured SECINFO flags*)
    is_reserved_zero( &(scratch_secinfo->reserved), sizeof(((secinfo_t *)0)->reserved), env);
    sgx_dbg( trace, "reserved zero check");

    if (!(scratch_secinfo->flags.page_type == PT_TCS || scratch_secinfo->flags.page_type == PT_TRIM)) {
        raise_exception(env, EXCP0D_GPF);
    }
    sgx_dbg( trace, "page_type check 1");

    // TODO:(* Check concurrency with SGX1 instructions on the EPC page *)
    epcm_index = epcm_linsearch((void *)target_addr, env);
    epcm_entry_t *epcm_epc = &epcm[epcm_index]; 

    // knh : condition check is wrong, so I fixed.... 
    if ( epcm_epc->valid == 0 || !(epcm_epc->page_type == PT_REG || epcm_epc->page_type == PT_TCS)) {
        raise_exception(env, EXCP0E_PAGE);
    }
    sgx_dbg( trace, "page_type check 2");

    // (* Check for mis-configured SECINFO flags*)
    if ((epcm_epc->read == 0) && (scratch_secinfo->flags.r == 0) &&
        (scratch_secinfo->flags.w != 0)) {
        env->eflags = 1;
        env->regs[R_EAX] = ERR_SGX_PAGE_NOT_MODIFIABLE;
        goto Done;
    }
    sgx_dbg( trace, "secinfo flags check");

    if (epcm_epc->pending != 0 || epcm_epc->modified != 0) {
        env->eflags = 1;
        env->regs[R_EAX] = ERR_SGX_PAGE_NOT_MODIFIABLE;
        goto Done;
    }
    sgx_dbg( trace, "pending check");

    //TODO: error in einittokenkey setting, skip...  
    //tmp_secs = get_secs_address( epcm_epc );
    //tmp_secs_host = cpu_load_secs(env, tmp_secs);
    //if (tmp_secs_host->attributes.einittokenkey == 0)
    //    raise_exception(env, EXCP0D_GPF);
    //sgx_dbg( trace, "einittokenkey check");

    //TODO: check concurrency with ETRACK

    epcm_epc->modified = 1;
    epcm_epc->read  = 0;
    epcm_epc->write = 0;
    epcm_epc->execute  = 0;
    epcm_epc->page_type = scratch_secinfo->flags.page_type;
#ifdef THREAD_PROTECTION
    epcm_epc->enclave_tcs = NULL;
#endif

    env->eflags &= ~(CC_Z);
    env->regs[R_EAX] = 0;

    cpu_stx_data( env, tmp_secinfo, scratch_secinfo, sizeof(secinfo_t));
    sgx_dbg( trace, "after cpu_stx_data");

    free( scratch_secinfo);

    // next instruction 
    env->cregs.CR_CURR_EIP = env->cregs.CR_NEXT_EIP;
    env->cregs.CR_ENC_INSN_RET = true;

    Done:
    env->eflags &= ~(CC_C | CC_P | CC_A | CC_O | CC_S );
}

static
void sgx_epa(CPUX86State *env)
{

    // RBX: PT_VA (In, Const)
    // RCX: EPC Addr(In, EA)
    uint64_t *epc_addr = (uint64_t *)env->regs[R_ECX];
    uint16_t epcm_index = 0;

    if(env->regs[R_EBX] != PT_VA || !(is_aligned(epc_addr, PAGE_SIZE))) {
        raise_exception(env, EXCP0D_GPF);
    }
    check_within_epc(epc_addr, env);

    // TODO (* Check concurrency with other SGX instructions *)

    // Check EPC page must be empty 
    epcm_index = epcm_search(epc_addr, env);
    if(epcm[epcm_index].valid != 0) {
        raise_exception(env, EXCP0D_GPF);
    }

    // Clears EPC page 
    void *empty_page = (void *)malloc(PAGE_SIZE);
    memset(empty_page, 0, PAGE_SIZE);
    cpu_stx_data(env, epc_addr, empty_page, PAGE_SIZE);
  
    epcm[epcm_index].page_type = PT_VA;
    epcm[epcm_index].enclave_addr = 0;
    epcm[epcm_index].blocked = 0;
    // Based on Spec ver2--------- 
    epcm[epcm_index].pending = 0;
    epcm[epcm_index].modified = 0;
    // --------------------------- 
    epcm[epcm_index].read = 0;
    epcm[epcm_index].write = 0;
    epcm[epcm_index].execute = 0;
    epcm[epcm_index].valid = 1;
#ifdef THREAD_PROTECTION
    epcm[epcm_index].enclave_tcs = 0;
#endif
 
    free(empty_page);
    sgx_dbg(trace, "epa finishes well");

}

static
void sgx_ewb(CPUX86State *env)
{
    // EAX: Error(Out)
    // RBX: Pageinfo Addr(In)
    // RCX: EPC addr(In)
    // RDX: VA slot addr(In)
    int epc_index = 0, va_index = 0;
    pageinfo_t *tmp_pageinfo_host;
    uint64_t *tmp_srcpge;
    uint64_t *tmp_srcpge_host;
    uint64_t *page_to_evict_host;
    pcmd_t *tmp_pcmd;
    pcmd_t *tmp_pcmd_host;
    secs_t *tmp_secs;
    secs_t *tmp_secs_host;
#ifdef THREAD_PROTECTION
    tcs_t *tmp_tcs = NULL;
    tcs_t *tmp_tcs_host = NULL;
    uint64_t tmp_pcmd_threadid;
#endif
    uint64_t tmp_pcmd_enclaveid;
    uint64_t VA_slot;
    mac_header_t tmp_header; //MAC Header
    memset(&tmp_header, 0, 128);
    unsigned char iv[] = {0,0,0,0,0,0,0,0,0,0,0,0}; //cch: IV is 12 bytes
    static uint64_t tmp_ver = 0x1122334455667788; //cch: The value can be initialized as a random value and then incremented every time 
    memcpy(iv, &tmp_ver, 8); //cch: 32bit left-shift VA value before passing it to the IV

    if (!(is_aligned(env->regs[R_EBX], 32)) ||
        !(is_aligned(env->regs[R_ECX], PAGE_SIZE))) {
        raise_exception(env, EXCP0D_GPF);
    }
    check_within_epc((void *)env->regs[R_ECX], env);

    if (!(is_aligned(env->regs[R_EDX], 8))) {
        raise_exception(env, EXCP0D_GPF);
    }
    check_within_epc((void *)env->regs[R_EDX], env);

    /* EPCPAGE and VASLOT should not resolve to the same EPC page */
    /*
    if(is_within_same_epc((void *)env->regs[R_ECX], (void *)env->regs[R_EDX], env)) {
        raise_exception(env, EXCP0D_GPF);
    }
    */
   
    tmp_pageinfo_host = cpu_ldx_data(env, (env->regs[R_EBX]), sizeof(pageinfo_t));
    page_to_evict_host = cpu_ldx_data(env, (env->regs[R_ECX]), EPC_SIZE);
    tmp_srcpge = tmp_pageinfo_host->srcpge;
    tmp_srcpge_host = (uint64_t *)malloc(EPC_SIZE);
    tmp_pcmd = tmp_pageinfo_host->pcmd;
    tmp_pcmd_host = (pcmd_t *)malloc(sizeof(pcmd_t));

    if((tmp_pageinfo_host->linaddr != 0) || (tmp_pageinfo_host->secs != 0)){
        raise_exception(env, EXCP0D_GPF);
    }
#ifdef THREAD_PROTECTION
    if((tmp_pageinfo_host->tcs != 0)){
        raise_exception(env, EXCP0D_GPF);
    }
#endif

    if(!(is_aligned(tmp_pcmd, 128)) || !(is_aligned(tmp_srcpge, PAGE_SIZE))) {
        raise_exception(env, EXCP0D_GPF);
    }

    /* TODO: Check for concurrent SGX instruction access to the page */

    /* TODO: Check if the VA Page is being removed or changed*/

    epc_index = epcm_search((void *)env->regs[R_ECX], env);
    va_index = epcm_search((void *)env->regs[R_EDX], env);
    /* Verify that EPCPAGE and VASLOT page are valid EPC pages and DS:RDX is VA */
    if((epcm[epc_index].valid == 0) || (epcm[va_index].valid == 0) ||
       (epcm[va_index].page_type != PT_VA)) {
        raise_exception(env, EXCP0D_GPF);
    }
    /* Perform page-type-specific exception checks */
    if((epcm[epc_index].page_type == PT_REG) || (epcm[epc_index].page_type == PT_TCS) || (epcm[epc_index].page_type == PT_TRIM)) {
        tmp_secs = get_secs_address(&epcm[epc_index]);
        tmp_secs_host = load_secs(tmp_secs);
        /* TODO: Check that EBLOCK has occurred correctly */
    }
#ifdef THREAD_PROTECTION
    if((epcm[epc_index].page_type == PT_REG) || (epcm[epc_index].page_type == PT_TRIM)) {
        tmp_tcs = get_tcs_address(&epcm[epc_index]);
        if(tmp_tcs != NULL){
            tmp_tcs_host = load_tcs(tmp_tcs);
        }
    }
#endif

    env->eflags &= ~(CC_Z | CC_C | CC_P | CC_A | CC_O | CC_S);
    env->regs[R_EAX] = 0x0;

    /* Perform page-type-specific checks */
    if((epcm[epc_index].page_type == PT_REG) || (epcm[epc_index].page_type == PT_TCS) || (epcm[epc_index].page_type == PT_TRIM)) {
        /* check to see if the page is evictable */
        if(epcm[epc_index].blocked == 0) {
            env->regs[R_EAX] = ERR_SGX_PAGE_NOT_BLOCKED;
            env->eflags |= CC_Z;
            goto ERROR_EXIT;
        }

        /* TODO: Check if tracking done correctly */

        /* Obtain EID to establish cryptographic binding betw the paged-out page and the enclave */
        tmp_header.eid = tmp_secs_host->eid_reserved.eid_pad.eid;

        /* Obtain EID as an enclave handle for software */
        tmp_pcmd_enclaveid = tmp_secs_host->eid_reserved.eid_pad.eid;
#ifdef THREAD_PROTECTION
        if(epcm[epc_index].page_type != PT_TCS){
            if(tmp_tcs != NULL && tmp_tcs_host != NULL){
                tmp_header.tid = tmp_tcs_host->tid; 
                tmp_pcmd_threadid = tmp_tcs_host->tid;
            }
            else{ //shared regular page
                tmp_header.tid = 0;
                tmp_pcmd_threadid = 0;
            }
        }
        else{ //epcm[epc_index].page_type == PT_TCS
            tmp_header.tid = 0;
            tmp_pcmd_threadid = 0;
        }
#endif
    }
    else if(epcm[epc_index].page_type == PT_SECS) {
    /*TODO: check that there are no child pages inside the enclave
      Skip this temporalily... please never swap out PT_SECS...
    */
#ifdef THREAD_PROTECTION
        tmp_header.tid = 0;
        tmp_pcmd_threadid = 0;
#endif 
    }
    else if(epcm[epc_index].page_type == PT_VA) {
        tmp_header.eid = 0;
#ifdef THREAD_PROTECTION
        tmp_header.tid = 0;
        tmp_pcmd_threadid = 0;
#endif 
        tmp_pcmd_enclaveid = 0;
    }
    tmp_header.linaddr = epcm[epc_index].enclave_addr;
    sgx_dbg(trace, "tmp_header.linaddr is %p", tmp_header.linaddr);
    tmp_header.secinfo.flags.page_type = epcm[epc_index].page_type;
    tmp_header.secinfo.flags.r = epcm[epc_index].read;
    tmp_header.secinfo.flags.w = epcm[epc_index].write;
    tmp_header.secinfo.flags.x = epcm[epc_index].execute;
    tmp_header.secinfo.flags.pending = epcm[epc_index].pending;
    tmp_header.secinfo.flags.modified = epcm[epc_index].modified;
    // it seems rsvd in the spec indicates reserved field.. but not sure.. cch: where?
    //TMP_HEADER.SECINFO.FLAGS.RSVD = 0;

    /* Encrypt the page, AES-GCM produces 2 values, {ciphertext, MAC}. */
    encrypt_epc((unsigned char *)page_to_evict_host, PAGE_SIZE, (unsigned char *)&tmp_header,
                sizeof(mac_header_t), gcm_key, iv, (unsigned char *)tmp_srcpge_host,
				(unsigned char *)tmp_pcmd_host->mac);

    memset(&tmp_pcmd_host->secinfo, 0 , sizeof(secinfo_t));
    tmp_pcmd_host->secinfo.flags.page_type = epcm[epc_index].page_type;
    tmp_pcmd_host->secinfo.flags.r = epcm[epc_index].read;
    tmp_pcmd_host->secinfo.flags.w = epcm[epc_index].write;
    tmp_pcmd_host->secinfo.flags.x = epcm[epc_index].execute;
    tmp_pcmd_host->secinfo.flags.pending = epcm[epc_index].pending;
    tmp_pcmd_host->secinfo.flags.modified = epcm[epc_index].modified;
    memset(tmp_pcmd_host->reserved, 0, sizeof(tmp_pcmd_host->reserved));
    tmp_pcmd_host->enclaveid = tmp_pcmd_enclaveid;
#ifdef THREAD_PROTECTION
    tmp_pcmd_host->threadid = tmp_pcmd_threadid;
#endif
    tmp_pageinfo_host->linaddr = epcm[epc_index].enclave_addr;

    VA_slot = cpu_ldq_data(env, (env->regs[R_EDX]));
    /*Check if version array slot was empty */
    if( VA_slot ){
        env->regs[R_EAX] = ERR_SGX_VA_SLOT_OCCUPIED;
        env->eflags |= CC_C;
    }
    VA_slot = tmp_ver;
    cpu_stq_data(env, (env->regs[R_EDX]), VA_slot);
    tmp_ver++; 
    epcm[epc_index].valid = 0;

    stx_raw(tmp_secs, tmp_secs_host, sizeof(secs_t));
    cpu_stx_data(env, (env->regs[R_EBX]), tmp_pageinfo_host, sizeof(pageinfo_t));
    cpu_stx_data(env, tmp_srcpge, tmp_srcpge_host, EPC_SIZE);
    cpu_stx_data(env, tmp_pcmd, tmp_pcmd_host, sizeof(pcmd_t));

    ERROR_EXIT:
#ifdef THREAD_PROTECTION
        if(tmp_tcs_host != NULL){
           free(tmp_tcs_host);
        }
#endif
        free(tmp_secs_host);
        free(tmp_pageinfo_host);    
        free(page_to_evict_host);
        free(tmp_srcpge_host);
        free(tmp_pcmd_host);
        env->eflags &= ~(CC_C | CC_P | CC_A | CC_O | CC_S);
    sgx_dbg(trace, "ewb finishes well");
}

static
void encls_intel_pubkey(CPUX86State *env)
{
    uint8_t *intel_pubKey = (uint8_t *)env->regs[R_EBX];

    // Set CSR_INTELPUBKEYHASH
    sha256(intel_pubKey, KEY_LENGTH,
           (unsigned char *)&(env->cregs.CSR_INTELPUBKEYHASH), 0);
}

static
void encls_epcm_clear(CPUX86State *env)
{
    epc_t *target = (epc_t *)env->regs[R_EBX];
    int target_index = epcm_search(target, env);
    epcm[target_index].valid = 0;
}

// Sanity checks data structures
static void sanity_check(void)
{
    assert(sizeof(secs_t) == 4096);
    assert(sizeof(attributes_t) == 16);
    assert(sizeof(tcs_t) == 4096);
    assert(sizeof(tcs_flags_t) == 8);
    assert(sizeof(gprsgx_t) == 192);
    assert(sizeof(ssa_t) == 4096);
#ifdef THREAD_PROTECTION
    assert(sizeof(pageinfo_t) == 40);
#else
    assert(sizeof(pageinfo_t) == 32);
#endif
    assert(sizeof(secinfo_flags_t) == 8);
    assert(sizeof(secinfo_t) == 64);
    assert(sizeof(sigstruct_t) == 1808);
    assert(sizeof(einittoken_t) == 304);
    assert(sizeof(keypolicy_t) == 2);
    assert(sizeof(keyrequest_t) == 512);
    assert(sizeof(keydep_t) == 544);
    assert(sizeof(pcmd_t) == 128);
    assert(sizeof(mac_header_t) == 128);
}

static void init_qenclave(void)
{
    int i = 0;
    for(i = 0; i < MAX_ENCLAVES; i++){
        memset(&(qenclaves[i]), 0, sizeof(qeid_t));
    }
}

#define KEY_PATH1 "../conf/device.key" 
#define KEY_PATH2 "conf/device.key"


//Initializes qemu with the EPC address
static void encls_qemu_init(CPUX86State *env)
{
    // firstPage represents the first page of EPC - the start of EPC
    epc_t *firstPage = (epc_t *)env->regs[R_EBX];
    epc_t *endPage = (epc_t *)env->regs[R_ECX];
    memset(epcm, 0, NUM_EPC * sizeof(epcm_entry_t));

    // Save the epc base and address
    // Made Base the previous value since it appears as an address inside is_within_epc (thus goes to mem_access
    // causing an unnecessary access violation due to the ranges itself.
    EPC_BaseAddr = (uint64_t)firstPage - 1;
    EPC_EndAddr  = (uint64_t)endPage;

    sgx_dbg(trace, "set EPC pages %p-%p",
            (void *)EPC_BaseAddr,
            (void *)EPC_EndAddr);

    int iter;

    for (iter = 0; iter < NUM_EPC; iter++) {
        epcm[iter].epcPageAddress = (uint64_t)firstPage;
        epcm[iter].epcHostAddress = return_hostaddr(env, (uint64_t)firstPage);
        //sgx_dbg(trace, "epcHostAddress is %p", epcm[iter].epcHostAddress);
        firstPage++;
    }

    // Initializing CR_ Registers in cpu.h (For CR_NEXT_EID)
    env->cregs.CR_NEXT_EID = 0; // Next Enclave EID
#ifdef THREAD_PROTECTION
    env->cregs.CR_NEXT_TID = 0; // Next Thread ID
#endif
    env->cregs.CR_ENC_INSN_RET = false;
    env->cregs.CR_EXIT_MODE = false;

    // Setting the SSA Base
    set_ssa_base();

    // Load device key pair
    if (file_exist(KEY_PATH1)){
        sgx_dbg(trace,"now first try %s\n", KEY_PATH1);
        load_rsa_keys(KEY_PATH1, process_pub_key, process_priv_key, DEVICE_KEY_LENGTH_BITS);
    }
    else{
        sgx_dbg(trace,"%s does not exist, now try %s\n", KEY_PATH1, KEY_PATH2);
        load_rsa_keys(KEY_PATH2, process_pub_key, process_priv_key, DEVICE_KEY_LENGTH_BITS);
    }

    // sanity check
    sanity_check();
}

static
void encls_set_cpusvn(CPUX86State *env)
{
    uint8_t *svn = (uint8_t *)env->regs[R_EBX];

    // Set CSR_CPUSVN
    env->cregs.CR_CPUSVN[1] = 0;
    env->cregs.CR_CPUSVN[0] = (uint64_t)svn;
}

static
void encls_set_stat(CPUX86State *env)
{
    int32_t eid = (int32_t)env->regs[R_EBX];
    stat_t *stat = (stat_t *)env->regs[R_ECX];
    cpu_stx_data(env, stat, &(qenclaves[eid].stat), sizeof(stat_t)); 
}

static
void encls_set_stack(CPUX86State *env)
{
    uint8_t *sp = (uint8_t *)env->regs[R_EBX];

    env->cregs.CR_EBP = (uint64_t)sp;
    env->cregs.CR_ESP = (uint64_t)sp;
}

static
const char *encls_cmd_to_str(long cmd) {
    switch (cmd) {
    case ENCLS_ECREATE:       return "ECREATE";
    case ENCLS_EADD:          return "EADD";
    case ENCLS_EINIT:         return "EINIT";
    case ENCLS_EREMOVE:       return "EREMOVE";
    case ENCLS_EEXTEND:       return "EEXTEND";
    case ENCLS_EAUG:          return "EAUG";
    case ENCLS_OSGX_INIT:     return "OSGX_INIT";
    case ENCLS_OSGX_PUBKEY:   return "OSGX_PUBKEY";
    case ENCLS_OSGX_EPCM_CLR: return "OSGX_EPCM_CLR";
    case ENCLS_OSGX_CPUSVN:   return "OSGX_CPUSVN";
    case ENCLS_OSGX_STAT:     return "OSGX_STAT";
    case ENCLS_OSGX_SET_STACK: return "OSGX_SET_STACK";
    }
    return "UNKONWN";
}

void helper_sgx_encls(CPUX86State *env)
{
    sgx_dbg(ttrace,
            "(%-13s) EAX=0x%08"PRIx64", EBX=0x%08"PRIx64", "
            "RCX=0x%08"PRIx64", RDX=0x%08"PRIx64,
            encls_cmd_to_str(env->regs[R_EAX]),
            env->regs[R_EAX],
            env->regs[R_EBX],
            env->regs[R_ECX],
            env->regs[R_EDX]);
    switch (env->regs[R_EAX]) {
        case ENCLS_ECREATE:
            sgx_ecreate(env);
            break;
        case ENCLS_EADD:
            sgx_eadd(env);
            break;
        case ENCLS_EINIT:
            sgx_einit(env);
            break;
        case ENCLS_ELDB:
        case ENCLS_ELDU:
            sgx_eldb(env);
            break;
        case ENCLS_EREMOVE:
           sgx_eremove(env);
            break;
        case ENCLS_EEXTEND:
            sgx_eextend(env);
            break;
        case ENCLS_EBLOCK:
            sgx_eblock(env);
            break;
        case ENCLS_EPA:
            sgx_epa(env);
            break;
        case ENCLS_EWB:
            sgx_ewb(env);
            break;
        case ENCLS_EAUG:
            sgx_eaug(env);
            break;
        case ENCLS_EMODPR:
            sgx_emodpr(env);
            break;
        case ENCLS_EMODT:
            sgx_emodt(env);
            break;

        // custom (non-spec) hypercalls: for setting up qemu
        case ENCLS_OSGX_INIT:
            init_qenclave(); // Initializing QEMU Enclave Descriptor
            encls_qemu_init(env);
            break;
        case ENCLS_OSGX_PUBKEY:
            encls_intel_pubkey(env);
            break;
        case ENCLS_OSGX_EPCM_CLR:
            encls_epcm_clear(env);
            break;
        case ENCLS_OSGX_CPUSVN:
            encls_set_cpusvn(env);
            break;
        case ENCLS_OSGX_STAT:
            encls_set_stat(env);
            break;
        case ENCLS_OSGX_SET_STACK:
            encls_set_stack(env);
            break;
        default:
            sgx_err("not implemented yet");
    }
}

void helper_sgx_ehandle(CPUX86State *env, int intno, int is_int) 
{
    // Save RIP for later use
    secs_t *secs;
    gprsgx_t *tmp_gpr;
    bool tmp_mode64;
    tcs_t *tcs;
    tcs_t *tmp_tcs_host;

    if (is_int) {
          sgx_dbg(info, "Entered Interrupt Handler QEMU interrupt no. is %d", intno);
    } else {
          sgx_dbg(info, "Entered Exception Handler QEMU exception no. is %d", intno);
    }

    secs = (secs_t *)env->cregs.CR_ACTIVE_SECS;

    secs_t *tmp_secs = load_secs(secs); // cch: needs to be freed later
    tmp_gpr = (gprsgx_t *)(env->cregs.CR_GPR_PA); //CR_XSAVE_PAGE[0];
    gprsgx_t* tmp_gpr_host = cpu_ldx_data(env, tmp_gpr, sizeof(gprsgx_t));

    // Check for 64 bit mode
    tmp_mode64 = (env->efer & MSR_EFER_LMA) && (env->segs[R_CS].flags & DESC_L_MASK);

    /* (* Save all registers, When saving EFLAGS, the TF bit is set to 0 and
       the RF bit is set to what would have been saved on stack in the non-SGX case *) */

    if (!tmp_mode64) {
        saveState(tmp_gpr_host, env); //cch:tmp_gpr_host should instead be used
        //TODO:    tmp_ssa->rflags.tf = 0;
    } else {
        saveState(tmp_gpr_host, env);
        //TODO:    tmp_ssa->rflags.tf = 0;
    }
    //cch added for making exception event synced with eexit(trampoline). this is not in spec
    tmp_gpr_host->SAVED_EXIT_EIP = env->cregs.CR_EXIT_EIP;

    //TODO: save FS and GS base into SSA using CR_GPR_PA CCH: why?
#if DEBUG
    sgx_msg(info, "Ssaved the state");
#endif
    /* (* Use a special version of XSAVE that takes a list of physical addresses of logically sequential pages to
    perform the save. TMP_MODE64 specifies whether to use the 32-bit or 64-bit layout.
    SECS.ATTRIBUTES.XFRM selects the features to be saved.
    CR_XSAVE_PAGE_n specifies a list of 1 or more physical addresses of pages that contain the XSAVE area. *)*/
    xsave(tmp_mode64, tmp_secs->attributes.xfrm, env->cregs.CR_XSAVE_PAGE[0]);  // N = 0; TODO
    /* (* Clear bytes 8 to 23 of XSAVE_HEADER, i.e. the next 16 bytes after XHEADER_BV *) */
    clearBytes(env->cregs.CR_XSAVE_PAGE, 0); //TODO
    /* (* Clear bits in XHEADER_BV[63:0] that are not enabled in ATTRIBUTES.XFRM *)*/
    assignBits(env->cregs.CR_XSAVE_PAGE, secs); //TODO
    // (* Restore the outside RSP and RBP from the current SSA frame.
    // This is where they had been stored on most recent EENTER *)
    // XXX: Obtain from the TMP_SSA dedicated to the current EID
    sgx_dbg(trace, "Before ESP: %lx   EBP: %lx", env->regs[R_ESP], env->regs[R_EBP]);

    env->regs[R_ESP] = tmp_gpr_host->ursp;
    env->regs[R_EBP] = tmp_gpr_host->urbp;

    sgx_dbg(trace, "After ESP: %lx   EBP: %lx", env->regs[R_ESP], env->regs[R_EBP]);
    // Restore FS and GS
    env->segs[R_FS].base = env->cregs.CR_SAVE_FS.base;
    env->segs[R_FS].limit = env->cregs.CR_SAVE_FS.limit;
    env->segs[R_FS].flags = env->cregs.CR_SAVE_FS.flags;
    env->segs[R_FS].selector = env->cregs.CR_SAVE_FS.selector;

    env->segs[R_GS].base = env->cregs.CR_SAVE_GS.base;
    env->segs[R_GS].limit = env->cregs.CR_SAVE_GS.limit;
    env->segs[R_GS].flags = env->cregs.CR_SAVE_GS.flags;
    env->segs[R_GS].selector = env->cregs.CR_SAVE_GS.selector;

    if ((intno == EXCP00_DIVZ) || (intno == EXCP01_DB) || (intno == EXCP03_INT3) || (intno == EXCP05_BOUND) || (intno == EXCP06_ILLOP) ||
        (intno == EXCP10_COPR) || (intno == EXCP11_ALGN)){ //cch: XM is not supported in QEMU
         tmp_gpr_host->exitinfo.vector = intno;
         if (intno == EXCP03_INT3){
              tmp_gpr_host->exitinfo.exit_type = 6;
         }
         else{
              tmp_gpr_host->exitinfo.exit_type = 3;
         }
         tmp_gpr_host->exitinfo.valid = 1;
    }
    else if ((intno == EXCP0E_PAGE) || (intno == EXCP0D_GPF)){
         if (tmp_secs->miscselect.exinfo == 1){
              tmp_gpr_host->exitinfo.vector = intno;
              tmp_gpr_host->exitinfo.exit_type = 3;
              if (intno == EXCP0E_PAGE){
                   //TODO
              }
              else{
                   //TODO
              }
              tmp_gpr_host->exitinfo.valid = 1;
         }
         else{
              tmp_gpr_host->exitinfo.vector = 0;
              tmp_gpr_host->exitinfo.exit_type = 0;
              tmp_gpr_host->exitinfo.valid = 0;
         }
    }

    sgx_dbg(trace, "Was at EIP:  %"PRIx64"", env->eip);
    //cch: do I need to set EIP as AEP so that exception handler can return to this point -> yes
    env->eip = env->cregs.CR_AEP;
    sgx_dbg(trace, "Now at EIP:  %"PRIx64"", env->eip);
    // Set EAX to the ERESUME leaf index
    env->regs[R_EAX] = ENCLU_ERESUME;
    // Put the TCS LA into RBX for later use by ERESUME
    env->regs[R_EBX] = env->cregs.CR_TCS_LA;
    sgx_dbg(trace, "CR_TCS_LA in ehandle: %p", env->cregs.CR_TCS_LA);
    // Put the AEP into RCX for later use by ERESUME
    env->regs[R_ECX] = env->cregs.CR_AEP;
    // Update the SSA frame #

    tcs = (tcs_t *)env->cregs.CR_TCS_LA;
    tmp_tcs_host = cpu_ldx_data(env, tcs, sizeof(tcs_t));
    tmp_tcs_host->cssa += 1;

    // (* Restore XCR0 if needed *)
    if ((env->cr[4] & CR4_OSXSAVE_MASK)) {
        env->xcr0 = env->cregs.CR_SAVE_XCR0;
    }

    env->cregs.CR_ENCLAVE_MODE = false;

    //TODO: CR_DBGOPTIN check
    //TODO: VMCS check
    //TODO: if (exception is %PF) cr2 <- cr2 & ~0xFFFF;

    cpu_stx_data(env, tmp_gpr, tmp_gpr_host, sizeof(gprsgx_t));
    cpu_stx_data(env, tcs, tmp_tcs_host, sizeof(tcs_t));
    free(tmp_gpr_host);
    free(tmp_secs);
    free(tmp_tcs_host);

    sgx_msg(info, "Exception Check- Gets redirected to the appropriate exception Handler");
    return;
}

void helper_sgx_trace_pc(target_ulong pc)
{
    sgx_dbg(trace, "pc = %p", (void *)pc);
}

/* Local hack for rdrand instruction------------
   it just read /dev/random from the host and returns
   the value to the specific register.
   it could trigger erro if it is called too frequently,
   because /dev/random's pool is generated from the HW based
   entropy and can be exhausted...  */
void helper_rdrand(CPUX86State *env, uint32_t regSize , uint32_t modrm)
{
    char random[8];
    int result = 0;
    int fd = open("/dev/random", O_RDONLY);
    int rm = 0;

    if(fd == -1) {
        printf("file open error: /dev/random\n");
        return;
    }
    memset(random, 0, 8);

    switch(regSize) {
        case 16:
            result = read(fd, random, 2);
            if(result != 2){
                goto ERROR;
            }
            break;
        case 32:
            result = read(fd, random, 4);
            if(result != 4){
                goto ERROR;
            }
            break;
        case 64:
            result = read(fd, random, 8);
            if(result != 8){
                goto ERROR;
            }
            break;
        default:
            break;

    }
    rm = modrm & 7; // rm indicate register RAX ~ EDI
    memset(&env->regs[rm], 0, sizeof(target_ulong)); // clear reg
    memcpy(&env->regs[rm], random, regSize/8); //copy random value

    // Rdrand success CF = 1
    env->eflags |= (CC_C);

    // Clear flags
    env->eflags &= ~(CC_O | CC_S | CC_Z | CC_A | CC_P);
    close(fd);
    return;

ERROR:
    // Rdrand fail CF = 0
    printf("read error: /dev/random\n");
    env->eflags &= ~(CC_C);
    return;
}
