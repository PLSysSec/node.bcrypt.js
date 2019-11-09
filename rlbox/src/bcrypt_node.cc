#include <nan.h>

#include <string>
#include <cstring>
#include <vector>
#include <stdlib.h> // atoi

#include "node_blf.h"

#if defined(RLBOX_NACL)
#include "RLBox_NaCl.h"
using T_SandboxType = RLBox_NaCl;
const char* SANDBOX_RUNTIME = "../../Sandboxing_NaCl/native_client/scons-out/nacl_irt-x86-64/staging/irt_core.nexe";
const char* SANDBOX_PROGRAM = "./bcrypt.nexe"; 
#else
#include "RLBox_DynLib.h"
using T_SandboxType = RLBox_DynLib;
const char* SANDBOX_RUNTIME = "";
const char* SANDBOX_PROGRAM = "./bcrypt.so"; 
#endif
#include "rlbox.h"

using namespace rlbox;

#define NODE_LESS_THAN (!(NODE_VERSION_AT_LEAST(0, 5, 4)))

using namespace v8;
using namespace node;


namespace rlbox {
  tainted<char*, T_SandboxType> copyStrToSandbox(RLBoxSandbox<T_SandboxType>* sandbox, const char* str) {
    size_t len = strlen(str);

    tainted<char*, T_SandboxType> sandboxStr = sandbox->template mallocInSandbox<char>(len + 1);
    memcpy(sandbox, sandboxStr, str, len + 1);
    return sandboxStr;
  }
}

namespace {

RLBoxSandbox<T_SandboxType>* sandbox;

bool ValidateSalt(const char* salt) {

    if (!salt || *salt != '$') {
        return false;
    }

    // discard $
    salt++;

    if (*salt > BCRYPT_VERSION) {
        return false;
    }

    if (salt[1] != '$') {
        switch (salt[1]) {
        case 'a':
        case 'b':
            salt++;
            break;
        default:
            return false;
        }
    }

    // discard version + $
    salt += 2;

    if (salt[2] != '$') {
        return false;
    }

    int n = atoi(salt);
    if (n > 31 || n < 0) {
        return false;
    }

    if (((uint8_t)1 << (uint8_t)n) < BCRYPT_MINROUNDS) {
        return false;
    }

    salt += 3;
    if (strlen(salt) * 3 / 4 < BCRYPT_MAXSALT) {
        return false;
    }

    return true;
}

char ToCharVersion(Local<String> str) {
  //String::Utf8Value value(str);

  std::string our_str = *Nan::Utf8String(str);

  return our_str[0];
}

/* SALT GENERATION */

class SaltAsyncWorker : public Nan::AsyncWorker {
public:
    SaltAsyncWorker(Nan::Callback *callback, std::string seed, ssize_t rounds, char minor_ver)
        : Nan::AsyncWorker(callback, "bcrypt:SaltAsyncWorker"), seed(seed),
          rounds(rounds), minor_ver(minor_ver) {
    }

    ~SaltAsyncWorker() {}

    void Execute() {
        // REWROTE:
        // char salt[_SALT_LEN];
        // bcrypt_gensalt(minor_ver, rounds, (u_int8_t *)&seed[0], salt);
        // TO:
        tainted<u_int8_t*, T_SandboxType> seedCopy = sandbox->template mallocInSandbox<u_int8_t>(BCRYPT_MAXSALT);
        memcpy(sandbox, seedCopy, (u_int8_t *)&seed[0], BCRYPT_MAXSALT);

        tainted<char*, T_SandboxType> saltOut = sandbox->template mallocInSandbox<char>(_SALT_LEN);
        sandbox_invoke(sandbox, bcrypt_gensalt,
                      minor_ver, rounds, seedCopy, saltOut);
        char* salt = saltOut.copyAndVerifyString(sandbox, [](char* val) { return strlen(val) < _SALT_LEN ? RLBox_Verify_Status::SAFE : RLBox_Verify_Status::UNSAFE; }, nullptr);
        // END
        this->salt = std::string(salt);
    }

    void HandleOKCallback() {
        Nan::HandleScope scope;

        Local<Value> argv[2];
        argv[0] = Nan::Undefined();
        argv[1] = Nan::Encode(salt.c_str(), salt.size(), Nan::BINARY);
        callback->Call(2, argv, async_resource);
    }

private:
    std::string seed;
    std::string salt;
    ssize_t rounds;
    char minor_ver;
};

NAN_METHOD(GenerateSalt) {
    Nan::HandleScope scope;

    if (info.Length() < 4) {
        Nan::ThrowTypeError("4 arguments expected");
        return;
    }

    if(!info[0]->IsString()) {
        Nan::ThrowTypeError("First argument must be a string");
        return;
    }

    if (!Buffer::HasInstance(info[2]) || Buffer::Length(info[2].As<Object>()) != 16) {
        Nan::ThrowTypeError("Third argument must be a 16 byte Buffer");
        return;
    }

    const char minor_ver = ToCharVersion(Nan::To<v8::String>(info[0]).ToLocalChecked());
    const int32_t rounds = Nan::To<int32_t>(info[1]).FromMaybe(0);
    Local<Object> seed = info[2].As<Object>();
    Local<Function> callback = Local<Function>::Cast(info[3]);

    SaltAsyncWorker* saltWorker = new SaltAsyncWorker(new Nan::Callback(callback),
        std::string(Buffer::Data(seed), 16), rounds, minor_ver);

    Nan::AsyncQueueWorker(saltWorker);
}

NAN_METHOD(GenerateSaltSync) {
    Nan::HandleScope scope;

    if (info.Length() < 3) {
        Nan::ThrowTypeError("2 arguments expected");
        return;
    }

    if(!info[0]->IsString()) {
        Nan::ThrowTypeError("First argument must be a string");
        return;
    }

    if (!Buffer::HasInstance(info[2]) || Buffer::Length(info[2].As<Object>()) != 16) {
        Nan::ThrowTypeError("Third argument must be a 16 byte Buffer");
        return;
    }

    const char minor_ver = ToCharVersion(Nan::To<v8::String>(info[0]).ToLocalChecked());
    const int32_t rounds = Nan::To<int32_t>(info[1]).FromMaybe(0);
    u_int8_t* seed = (u_int8_t*)Buffer::Data(info[2].As<Object>());

    // REWROTE:
    // char salt[_SALT_LEN];
    // bcrypt_gensalt(minor_ver, rounds, seed, salt);
    // TO:
    tainted<u_int8_t*, T_SandboxType> seedCopy = sandbox->template mallocInSandbox<u_int8_t>(BCRYPT_MAXSALT);
    memcpy(sandbox, seedCopy, seed, BCRYPT_MAXSALT);

    tainted<char*, T_SandboxType> saltOut = sandbox->template mallocInSandbox<char>(_SALT_LEN);
    sandbox_invoke(sandbox, bcrypt_gensalt,
                   minor_ver, rounds, seedCopy, saltOut);
    char* salt = saltOut.copyAndVerifyString(sandbox, [](char* val) { return strlen(val) < _SALT_LEN ? RLBox_Verify_Status::SAFE : RLBox_Verify_Status::UNSAFE; }, nullptr);
    sandbox->freeInSandbox(seedCopy);
    sandbox->freeInSandbox(saltOut);
    // END

    info.GetReturnValue().Set(Nan::Encode(salt, strlen(salt), Nan::BINARY));
}

/* ENCRYPT DATA - USED TO BE HASHPW */

class EncryptAsyncWorker : public Nan::AsyncWorker {
  public:
    EncryptAsyncWorker(Nan::Callback *callback, std::string input, std::string salt)
        : Nan::AsyncWorker(callback, "bcrypt:EncryptAsyncWorker"), input(input),
          salt(salt) {
    }

    ~EncryptAsyncWorker() {}

    void Execute() {
        if (!(ValidateSalt(salt.c_str()))) {
            error = "Invalid salt. Salt must be in the form of: $Vers$log2(NumRounds)$saltvalue";
        }

        // REWROTE:
        // char bcrypted[_PASSWORD_LEN];
        // bcrypt(input.c_str(), salt.c_str(), bcrypted);
        // TO:
        tainted<char*, T_SandboxType> bcryptedOut = sandbox->template mallocInSandbox<char>(_PASSWORD_LEN);
        tainted<char*, T_SandboxType> inputStr = copyStrToSandbox(sandbox, input.c_str());
        tainted<char*, T_SandboxType> saltStr  = copyStrToSandbox(sandbox, salt.c_str());
        sandbox_invoke(sandbox, bcrypt, inputStr, saltStr, bcryptedOut);

        const char* bcrypted = bcryptedOut.copyAndVerifyString(sandbox, [](char* val) { return strlen(val) < _PASSWORD_LEN ? RLBox_Verify_Status::SAFE : RLBox_Verify_Status::UNSAFE; }, nullptr);
        sandbox->freeInSandbox(bcryptedOut);
        sandbox->freeInSandbox(inputStr);
        sandbox->freeInSandbox(saltStr);
        // END
        output = std::string(bcrypted);
    }

    void HandleOKCallback() {
        Nan::HandleScope scope;

        Local<Value> argv[2];

        if (!error.empty()) {
            argv[0] = Nan::Error(error.c_str());
            argv[1] = Nan::Undefined();
        } else {
            argv[0] = Nan::Undefined();
            argv[1] = Nan::Encode(output.c_str(), output.size(), Nan::BINARY);
        }

        callback->Call(2, argv, async_resource);
    }

  private:
    std::string input;
    std::string salt;
    std::string error;
    std::string output;
};

NAN_METHOD(Encrypt) {
    Nan::HandleScope scope;

    if (info.Length() < 3) {
        Nan::ThrowTypeError("3 arguments expected");
        return;
    }

    Nan::Utf8String data(Nan::To<v8::String>(info[0]).ToLocalChecked());
    Nan::Utf8String salt(Nan::To<v8::String>(info[1]).ToLocalChecked());
    Local<Function> callback = Local<Function>::Cast(info[2]);

    EncryptAsyncWorker* encryptWorker = new EncryptAsyncWorker(new Nan::Callback(callback),
        std::string(*data), std::string(*salt));

    Nan::AsyncQueueWorker(encryptWorker);
}

NAN_METHOD(EncryptSync) {
    Nan::HandleScope scope;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("2 arguments expected");
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    Nan::Utf8String data(Nan::To<v8::String>(info[0]).ToLocalChecked());
    Nan::Utf8String salt(Nan::To<v8::String>(info[1]).ToLocalChecked());

    if (!(ValidateSalt(*salt))) {
        Nan::ThrowError("Invalid salt. Salt must be in the form of: $Vers$log2(NumRounds)$saltvalue");
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    // REWROTE:
    // char bcrypted[_PASSWORD_LEN];
    // bcrypt(*data, *salt, bcrypted);
    // TO:
    tainted<char*, T_SandboxType> bcryptedOut = sandbox->template mallocInSandbox<char>(_PASSWORD_LEN);
    tainted<char*, T_SandboxType> dataStr = copyStrToSandbox(sandbox, *data);
    tainted<char*, T_SandboxType> saltStr = copyStrToSandbox(sandbox, *salt);
    sandbox_invoke(sandbox, bcrypt, dataStr, saltStr, bcryptedOut);

    const char* bcrypted = bcryptedOut.copyAndVerifyString(sandbox, [](char* val) { return strlen(val) < _PASSWORD_LEN ? RLBox_Verify_Status::SAFE : RLBox_Verify_Status::UNSAFE; }, nullptr);
    sandbox->freeInSandbox(bcryptedOut);
    sandbox->freeInSandbox(dataStr);
    sandbox->freeInSandbox(saltStr);
    // END
    info.GetReturnValue().Set(Nan::Encode(bcrypted, strlen(bcrypted), Nan::BINARY));
}

/* COMPARATOR */

NAN_INLINE bool CompareStrings(const char* s1, const char* s2) {

    bool eq = true;
    int s1_len = strlen(s1);
    int s2_len = strlen(s2);

    if (s1_len != s2_len) {
        eq = false;
    }

    const int max_len = (s2_len < s1_len) ? s1_len : s2_len;

    // to prevent timing attacks, should check entire string
    // don't exit after found to be false
    for (int i = 0; i < max_len; ++i) {
      if (s1_len >= i && s2_len >= i && s1[i] != s2[i]) {
        eq = false;
      }
    }

    return eq;
}

class CompareAsyncWorker : public Nan::AsyncWorker {
  public:
    CompareAsyncWorker(Nan::Callback *callback, std::string input, std::string encrypted)
        : Nan::AsyncWorker(callback, "bcrypt:CompareAsyncWorker"), input(input),
          encrypted(encrypted) {

        result = false;
    }

    ~CompareAsyncWorker() {}

    void Execute() {
        if (ValidateSalt(encrypted.c_str())) {
            // REWROTE:
            // char bcrypted[_PASSWORD_LEN];
            // bcrypt(input.c_str(), encrypted.c_str(), bcrypted);
            // TO:
            tainted<char*, T_SandboxType> bcryptedOut = sandbox->template mallocInSandbox<char>(_PASSWORD_LEN);
            sandbox_invoke(sandbox, bcrypt,
                          copyStrToSandbox(sandbox, input.c_str()),
                          copyStrToSandbox(sandbox, encrypted.c_str()), bcryptedOut);

            const char* bcrypted = bcryptedOut.copyAndVerifyString(sandbox, [](char* val) { return strlen(val) < _PASSWORD_LEN ? RLBox_Verify_Status::SAFE : RLBox_Verify_Status::UNSAFE; }, nullptr);
            sandbox->freeInSandbox(bcryptedOut);
            // END
            result = CompareStrings(bcrypted, encrypted.c_str());
        }
    }

    void HandleOKCallback() {
        Nan::HandleScope scope;

        Local<Value> argv[2];
        argv[0] = Nan::Undefined();
        argv[1] = Nan::New<Boolean>(result);
        callback->Call(2, argv, async_resource);
    }

  private:
    std::string input;
    std::string encrypted;
    bool result;
};

NAN_METHOD(Compare) {
    Nan::HandleScope scope;

    if (info.Length() < 3) {
        Nan::ThrowTypeError("3 arguments expected");
        return;
    }

    Nan::Utf8String input(Nan::To<v8::String>(info[0]).ToLocalChecked());
    Nan::Utf8String encrypted(Nan::To<v8::String>(info[1]).ToLocalChecked());
    Local<Function> callback = Local<Function>::Cast(info[2]);

    CompareAsyncWorker* compareWorker = new CompareAsyncWorker(new Nan::Callback(callback),
        std::string(*input), std::string(*encrypted));

    Nan::AsyncQueueWorker(compareWorker);
}

NAN_METHOD(CompareSync) {
    Nan::HandleScope scope;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("2 arguments expected");
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    Nan::Utf8String pw(Nan::To<v8::String>(info[0]).ToLocalChecked());
    Nan::Utf8String hash(Nan::To<v8::String>(info[1]).ToLocalChecked());

    if (ValidateSalt(*hash)) {
        // REWROTE:
        // char bcrypted[_PASSWORD_LEN];
        // bcrypt(*pw, *hash, bcrypted);
        // TO:
        tainted<char*, T_SandboxType> bcryptedOut = sandbox->template mallocInSandbox<char>(_PASSWORD_LEN);
        tainted<char*, T_SandboxType> pwStr = copyStrToSandbox(sandbox, *pw);
        tainted<char*, T_SandboxType> hashStr = copyStrToSandbox(sandbox, *hash);
        sandbox_invoke(sandbox, bcrypt, pwStr, hashStr, bcryptedOut); 
        const char* bcrypted = bcryptedOut.copyAndVerifyString(sandbox, [](char* val) { return strlen(val) < _PASSWORD_LEN ? RLBox_Verify_Status::SAFE : RLBox_Verify_Status::UNSAFE; }, nullptr);
        sandbox->freeInSandbox(bcryptedOut);
        sandbox->freeInSandbox(pwStr);
        sandbox->freeInSandbox(hashStr);
        // END
        info.GetReturnValue().Set(Nan::New<Boolean>(CompareStrings(bcrypted, *hash)));
    } else {
        info.GetReturnValue().Set(Nan::False());
    }
}

NAN_METHOD(GetRounds) {
    Nan::HandleScope scope;

    if (info.Length() < 1) {
        Nan::ThrowTypeError("1 argument expected");
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    Nan::Utf8String hash(Nan::To<v8::String>(info[0]).ToLocalChecked());
    // REWROTE:
    // u_int32_t rounds;
    // if (!(rounds = bcrypt_get_rounds(*hash))) {
    //     Nan::ThrowError("invalid hash provided");
    //     info.GetReturnValue().Set(Nan::Undefined());
    //     return;
    // }
    // TO:
    tainted<char*, T_SandboxType> hashStr = copyStrToSandbox(sandbox, *hash);
    u_int32_t rounds =
      sandbox_invoke(sandbox, bcrypt_get_rounds, hashStr).UNSAFE_Unverified();
    sandbox->freeInSandbox(hashStr);
    if (!rounds) {
      Nan::ThrowError("invalid hash provided");
      info.GetReturnValue().Set(Nan::Undefined());
      return;
    }
    // END

    info.GetReturnValue().Set(Nan::New(rounds));
}

} // anonymous namespace

NAN_MODULE_INIT(init) {
    sandbox = RLBoxSandbox<T_SandboxType>::createSandbox(SANDBOX_RUNTIME, SANDBOX_PROGRAM);
    Nan::Export(target, "gen_salt_sync", GenerateSaltSync);
    Nan::Export(target, "encrypt_sync", EncryptSync);
    Nan::Export(target, "compare_sync", CompareSync);
    Nan::Export(target, "get_rounds", GetRounds);
    Nan::Export(target, "gen_salt", GenerateSalt);
    Nan::Export(target, "encrypt", Encrypt);
    Nan::Export(target, "compare", Compare);
};

NODE_MODULE(bcrypt_lib, init);
