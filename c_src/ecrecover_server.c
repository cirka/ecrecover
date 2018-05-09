#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "secp256k1_recovery.h"


secp256k1_context *context;

// PORT application
// Read one char from stdin or exit(1) if stdin is closed as per Erlang port
// requirements
unsigned char take_char(){
    unsigned char taken;
    int count;

    while ( ( count = read(STDIN_FILENO, &taken, 1)) < 1 ) { if (count == 0) _exit(1);}
    return taken;
}

void put_char( unsigned char value) {
    if( write(STDOUT_FILENO, &value, 1) < 0 ) exit (2);
}

// Read 4 bytes and convert big endiand -> low endian
unsigned int take_int(){
    unsigned char *val_p;
    unsigned int offset, val;

    val_p = (unsigned char *)  & val;
    for(offset=0;offset <4;offset ++) val_p[4-1-offset] = take_char();
    return val;
}

// convert uint32 from low to high endian and write it 
void put_int(unsigned int value) {
    unsigned char *val_p;
    unsigned int offset;

    val_p = (unsigned char *)  & value;
    for(offset=0;offset<4;offset ++)  put_char(val_p[4-1-offset] );
}

unsigned char *take_bin(unsigned int length){
    unsigned char * buffer;
    uint32_t i = 0 ;
    uint32_t count;

    if( ! (buffer =  malloc(length))) { errno = 1; return 0;};
    while (i < length) {
     count = read(STDIN_FILENO, buffer + i, length - i);
     if (count < 1 ) _exit(2);  
     i = i + count;
    }
    return buffer;
}

void put_bin(unsigned char *buffer, uint32_t bin_len) {
    uint32_t i = 0;
    uint32_t count;

 while( i < bin_len) {
    count = write(STDOUT_FILENO, buffer + i, bin_len - i);
    if (count < 1) _exit(3);
    i = i + count;
    }
}

unsigned char *read_request(){
    uint32_t frame_length;

    frame_length = take_int();
    // validate request size return 
    if( frame_length == 97 || frame_length == 98) return take_bin(frame_length); 
   _exit(6); 
}


 void printdec(unsigned char *src, uint32_t length){
 unsigned char * addr;

 for(addr = src ; addr < src + length; addr ++) printf("%d ", * addr);
 }

void handle_sign(unsigned char *input, unsigned char **response, uint32_t *response_size){
 int result;
 secp256k1_ecdsa_recoverable_signature *signature;
 unsigned char * out;
 int recoveryid;

 signature = malloc(sizeof(secp256k1_ecdsa_recoverable_signature));
 memset(signature, 0, sizeof(secp256k1_ecdsa_recoverable_signature));
 if( ! signature) { perror("malloc"); _exit(12);}
 out = malloc(66);
 memset(out, 0, 66);
 if(! out ) { perror("malloc"); _exit(12);}
 result = secp256k1_ecdsa_sign_recoverable(context, signature, input, (input + 32), NULL, (input + 64));
 if (! result) // if failed to sign
 { 
  out[0] = 1;
  * response_size = 1;
 return ;
 }
 out[0] = 0;
 secp256k1_ecdsa_recoverable_signature_serialize_compact(context, (out + 1), &recoveryid, signature);
 out[65] = recoveryid && 0xff;
 free(signature);
 *response = out;
 *response_size = 66;
 }
 
void handle_recover(unsigned char *input, unsigned char **response, uint32_t *response_size) {
 int result;
 secp256k1_ecdsa_recoverable_signature *signature;
 secp256k1_pubkey *pub_key;
 unsigned char * out;
 size_t pubkey_size;


 signature = malloc(sizeof(secp256k1_ecdsa_recoverable_signature));
 if(! signature) { perror("malloc"); _exit(12);}
 memset(signature, 0, sizeof(secp256k1_ecdsa_recoverable_signature));
 result = secp256k1_ecdsa_recoverable_signature_parse_compact(context, signature, (input + 32), input[96]);
 if(! result){
   free(signature);
   out = malloc(1);
   out[0] = 1;
   *response = out;
   *response_size=1;
   return;
 }
 pub_key = malloc(sizeof(secp256k1_pubkey));
 if(! pub_key) { perror("malloc"); _exit(12);}
 memset(pub_key, 0, sizeof(secp256k1_pubkey));
 result = secp256k1_ecdsa_recover(context, pub_key, signature, input);
 free(signature);
 if(! result){
   free(pub_key);
   out = malloc(1);
   out[0] = 2;
   *response = out;
   *response_size=1;
   return;
 }
   out = malloc(66);
   out[0] = 0;
   pubkey_size = 65;
   secp256k1_ec_pubkey_serialize(context, (out + 1), &pubkey_size, pub_key, SECP256K1_EC_UNCOMPRESSED);
   free(pub_key);
   *response = out;
   *response_size=66;
   return;
}

void error_handler(const char *message, void *data) {
perror(message);
_exit(11);
}

int main() {
 unsigned char * request;
 uint32_t input_size;
 unsigned char * response;
 uint32_t response_size;

// Create library context
 if( ! (context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))) {
    perror("Could not allocate secp256k1 context");
    _exit(10);
 }

//install error handler
 secp256k1_context_set_illegal_callback(context, &error_handler, (void *) NULL);

 while (1) {
    request = read_request();
    switch (request[0]){
    case 0x01:
        handle_sign((request + 1), &response, &response_size);
        break;
    case 0x02:
        handle_recover((request + 1), &response, &response_size);
        break;
    default:
        _exit(5);
    }
    put_int(response_size);
    put_bin(response, response_size);
    free(request);
    free(response);
    fflush(stdout);
 }
}
