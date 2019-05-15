#include <stdint.h>
#include <stdlib.h>
#include <node_api.h>
#include <assert.h>

#include <openssl/conf.h>
#include <openssl/aes.h>

#include <string.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE AES_BLOCK_SIZE

typedef struct sane_aes_ctx_t  {
	AES_KEY key;
	uint8_t state[AES_BLOCK_SIZE];
} sane_aes_ctx_t;

napi_value hello(napi_env env, napi_callback_info info) {
  napi_status status;
  napi_value world;
  status = napi_create_string_utf8(env, "world", 5, &world);
  assert(status == napi_ok);
  return world;
}


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
	memcpy(ctx->state,iv_data,AES_BLOCK_SIZE);
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
	memcpy(ctx->state,iv_data,AES_BLOCK_SIZE);
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

	uint8_t *block_at=(uint8_t *)in_data;
	uint8_t *block_end=block_at+in_data_len;
	uint8_t *prev_cyphertext=ctx->state;
	uint8_t out[AES_BLOCK_SIZE];
	while (block_at<block_end) {
		for (int i=0; i<AES_BLOCK_SIZE; i++) block_at[i]=block_at[i] ^ prev_cyphertext[i];
		AES_encrypt(block_at,out,&ctx->key);
		for (int i=0; i<AES_BLOCK_SIZE; i++) block_at[i]=out[i];
		prev_cyphertext=block_at; block_at+=AES_BLOCK_SIZE;
	}
	for (int i=0; i<AES_BLOCK_SIZE; i++) ctx->state[i]=prev_cyphertext[i];
	
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

	uint8_t *block_at=(uint8_t *)in_data;
	uint8_t *block_end=block_at+in_data_len;
	uint8_t *prev_cyphertext=ctx->state;

	uint8_t out[AES_BLOCK_SIZE];
	while (block_at<block_end) {
		AES_decrypt(block_at,out,&ctx->key);
		for (int i=0; i<AES_BLOCK_SIZE; i++) {
			uint8_t store=out[i] ^ prev_cyphertext[i];
			prev_cyphertext[i]=block_at[i];
			block_at[i]=store;
		}

		block_at+=AES_BLOCK_SIZE;
	}
	return NULL;
}



#define DECLARE_NAPI_METHOD(name, func)                          \
  { name, 0, func, 0, 0, 0, napi_default, 0 }

napi_property_descriptor methods[]={
	DECLARE_NAPI_METHOD("hello", hello),
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
