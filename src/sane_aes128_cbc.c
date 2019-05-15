/*
	Copyright 2019 Stoian Ivanov

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License version 3.0 as published by the Free Software Foundation;

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

#include <stdint.h>
#include <stdlib.h>
#include <node_api.h>
#include <assert.h>

#include <openssl/conf.h>
#include <openssl/aes.h>

#include <string.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE AES_BLOCK_SIZE

#if __WORDSIZE == 64
#define AES_BLOCK_WORD uint64_t
typedef struct aes_block_t{ AES_BLOCK_WORD w[2]; } aes_block_t; //should be of size AES_BLOCK_SIZE
static inline void copy_state(aes_block_t *src,aes_block_t *dest) { dest->w[0]=src->w[0]; dest->w[1]=src->w[1]; };
static inline void xor_state(aes_block_t *src,aes_block_t *dest) { dest->w[0]^=src->w[0]; dest->w[1]^=src->w[1]; };
#else 
#define AES_BLOCK_WORD uint32_t
typedef struct aes_block_t{ AES_BLOCK_WORD w[4];} aes_block_t; //should be of size AES_BLOCK_SIZE
static inline void copy_state(aes_block_t *src,aes_block_t *dest) { dest->w[0]=src->w[0]; dest->w[1]=src->w[1]; dest->w[2]=src->w[2]; dest->w[3]=src->w[3]; };
static inline void xor_state(aes_block_t *src,aes_block_t *dest) { dest->w[0]^=src->w[0]; dest->w[1]^=src->w[1]; dest->w[2]^=src->w[2]; dest->w[3]^=src->w[3]; };
#endif


typedef struct sane_aes_ctx_t  {
	AES_KEY key;
	aes_block_t state;
} sane_aes_ctx_t;


napi_value getEncryptCtx(napi_env env, napi_callback_info info) {
	napi_status status;

	size_t argc = 2;
	napi_value args[2];
	status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	assert(status == napi_ok);
	if (argc!=2) {
		napi_throw_error(env, NULL, "Arguments should be TWO buffers containing key and iv");
		return NULL;
	};
	bool is_buf=false;
	if (napi_is_buffer(env,args[0],&is_buf)!=napi_ok) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	if (is_buf==false) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	is_buf=false;
	if (napi_is_buffer(env,args[1],&is_buf)!=napi_ok) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	if (is_buf==false) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}

	void *key_data; size_t key_data_len;
	void *iv_data; size_t iv_data_len;
	if (napi_get_buffer_info(env,args[0],&key_data,&key_data_len)!=napi_ok){
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	if (key_data_len!=AES_KEY_SIZE) {
		napi_throw_error(env, NULL, "key size mismatch");
		return NULL;
	}

	if (napi_get_buffer_info(env,args[1],&iv_data,&iv_data_len)!=napi_ok){
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	if (iv_data_len!=AES_BLOCK_SIZE) {
		napi_throw_error(env, NULL, "iv size mismatch");
		return NULL;
	}


	napi_value ctx_buf;
	sane_aes_ctx_t* ctx; 
	status = napi_create_buffer(env,sizeof(sane_aes_ctx_t), (void **)(&ctx), &ctx_buf);
	assert(status == napi_ok);
	AES_set_encrypt_key((unsigned char *)key_data,AES_KEY_SIZE*8,&ctx->key);
	memcpy(&ctx->state,iv_data,AES_BLOCK_SIZE);
	return ctx_buf;
}

napi_value getDecryptCtx(napi_env env, napi_callback_info info) {
	napi_status status;

	size_t argc = 2;
	napi_value args[2];
	status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	assert(status == napi_ok);
	if (argc!=2) {
		napi_throw_error(env, NULL, "Arguments should be TWO buffers containing key and iv");
		return NULL;
	};
	bool is_buf=false;
	if (napi_is_buffer(env,args[0],&is_buf)!=napi_ok) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	if (is_buf==false) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	is_buf=false;
	if (napi_is_buffer(env,args[1],&is_buf)!=napi_ok) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	if (is_buf==false) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}

	void *key_data; size_t key_data_len;
	void *iv_data; size_t iv_data_len;
	if (napi_get_buffer_info(env,args[0],&key_data,&key_data_len)!=napi_ok){
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	if (key_data_len!=AES_KEY_SIZE) {
		napi_throw_error(env, NULL, "key size mismatch");
		return NULL;
	}

	if (napi_get_buffer_info(env,args[1],&iv_data,&iv_data_len)!=napi_ok){
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing key and iv");
		return NULL;
	}
	if (iv_data_len!=AES_BLOCK_SIZE) {
		napi_throw_error(env, NULL, "iv size mismatch");
		return NULL;
	}


	napi_value ctx_buf;
	sane_aes_ctx_t* ctx; 
	status = napi_create_buffer(env,sizeof(sane_aes_ctx_t), (void **)(&ctx), &ctx_buf);
	assert(status == napi_ok);
	AES_set_decrypt_key((unsigned char *)key_data,AES_KEY_SIZE*8,&ctx->key);
	memcpy(&ctx->state,iv_data,AES_BLOCK_SIZE);
	return ctx_buf;
}



napi_value Encrypt(napi_env env, napi_callback_info info) {
	napi_status status;

	size_t argc = 2;
	napi_value args[2];
	status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	assert(status == napi_ok);
	if (argc!=2) {
		napi_throw_error(env, NULL, "Arguments should be TWO buffers containing ctx and buf");
		return NULL;
	};
	bool is_buf=false;
	if (napi_is_buffer(env,args[0],&is_buf)!=napi_ok) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	if (is_buf==false) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	is_buf=false;
	if (napi_is_buffer(env,args[1],&is_buf)!=napi_ok) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	if (is_buf==false) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}

	sane_aes_ctx_t* ctx; size_t ctx_len=0;
	void *in_data; size_t in_data_len;
	if (napi_get_buffer_info(env,args[0],(void**)&ctx,&ctx_len)!=napi_ok){
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	if (ctx_len!=sizeof(sane_aes_ctx_t)) {
		napi_throw_error(env, NULL, "ctx size mismatch");
		return NULL;
	}

	if (napi_get_buffer_info(env,args[1],&in_data,&in_data_len)!=napi_ok){
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	if (in_data_len==0 || (in_data_len % AES_BLOCK_SIZE)!=0) {
		napi_throw_error(env, NULL, "buffer lenght is 0 or is not padded");
		return NULL;
	}

	aes_block_t *block_at=(aes_block_t *)in_data;
	aes_block_t *block_end=(aes_block_t *)(in_data+in_data_len);
	aes_block_t *prev_cyphertext=&ctx->state;
	aes_block_t out;
	while (block_at<block_end) {
		xor_state(prev_cyphertext,block_at);
		AES_encrypt((const unsigned char*)block_at,(uint8_t*)&out,&ctx->key);
		copy_state(&out,block_at);
		prev_cyphertext=block_at; 
		block_at+=1;
	}
	copy_state(prev_cyphertext,&ctx->state);
	
	return NULL;
}




napi_value Decrypt(napi_env env, napi_callback_info info) {
	napi_status status;

	size_t argc = 2;
	napi_value args[2];
	status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	assert(status == napi_ok);
	if (argc!=2) {
		napi_throw_error(env, NULL, "Arguments should be TWO buffers containing ctx and buf");
		return NULL;
	};
	bool is_buf=false;
	if (napi_is_buffer(env,args[0],&is_buf)!=napi_ok) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	if (is_buf==false) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	is_buf=false;
	if (napi_is_buffer(env,args[1],&is_buf)!=napi_ok) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	if (is_buf==false) {
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}

	sane_aes_ctx_t* ctx; size_t ctx_len=0;
	void *in_data; size_t in_data_len;
	if (napi_get_buffer_info(env,args[0],(void**)&ctx,&ctx_len)!=napi_ok){
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	if (ctx_len!=sizeof(sane_aes_ctx_t)) {
		napi_throw_error(env, NULL, "ctx size mismatch");
		return NULL;
	}

	if (napi_get_buffer_info(env,args[1],&in_data,&in_data_len)!=napi_ok){
		napi_throw_error(env, NULL, "Arguments should be two BUFFERS containing ctx and buf");
		return NULL;
	}
	if (in_data_len==0 || (in_data_len % AES_BLOCK_SIZE)!=0) {
		napi_throw_error(env, NULL, "buffer lenght is 0 or is not padded");
		return NULL;
	}


	aes_block_t *block_at=(aes_block_t *)in_data;
	aes_block_t *block_end=(aes_block_t *)(in_data+in_data_len);
	aes_block_t *prev_cyphertext=&ctx->state;
	aes_block_t out;

	while (block_at<block_end) {
		AES_decrypt((const unsigned char*)&block_at->w,(unsigned char*)&out.w,&ctx->key);
		AES_BLOCK_WORD store;

		store=out.w[0] ^ prev_cyphertext->w[0];
		prev_cyphertext->w[0]=block_at->w[0];
		block_at->w[0]=store;

		store=out.w[1] ^ prev_cyphertext->w[1];
		prev_cyphertext->w[1]=block_at->w[1];
		block_at->w[1]=store;


		#if __WORDSIZE != 64

		store=out.w[2] ^ prev_cyphertext->w[2];
		prev_cyphertext->w[2]=block_at->w[2];
		block_at->w[2]=store;

		store=out.w[3] ^ prev_cyphertext->w[3];
		prev_cyphertext->w[3]=block_at->w[3];
		block_at->w[3]=store;

		#endif

		block_at+=1;
	}
	return NULL;
}



#define DECLARE_NAPI_METHOD(name, func) { name, 0, func, 0, 0, 0, napi_default, 0 }

napi_property_descriptor methods[]={
	DECLARE_NAPI_METHOD("getEncryptCtx", getEncryptCtx),
	DECLARE_NAPI_METHOD("getDecryptCtx", getDecryptCtx),
	DECLARE_NAPI_METHOD("Encrypt",Encrypt),
	DECLARE_NAPI_METHOD("Decrypt",Decrypt)
};

napi_value Init(napi_env env, napi_value exports) {
	napi_status status;


	status = napi_define_properties(env, exports, sizeof(methods)/sizeof(methods[0]), methods);
	assert(status == napi_ok);


	return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
