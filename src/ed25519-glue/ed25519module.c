
/* Use this file as a template to start implementing a module that
   also declares object types. All occurrences of 'FOOOBJ' should be changed
   to something reasonable for your objects. After that, all other
   occurrences of 'ed25519' should be changed to something reasonable for your
   module. If your module is named foo your sourcefile should be named
   foomodule.c.

   You will probably want to delete all references to 'x_attr' and add
   your own types of attributes instead.  Maybe you want to name your
   local variables other than 'self'.  If your object type is needed in
   other files, you'll have to create a file "foobarobject.h"; see
   intobject.h for an example. */

// this makes "s#" use Py_ssize_t instead of int
#define PY_SSIZE_T_CLEAN 1
#include "Python.h"

static PyObject *BadSignatureError,
    *SECRETKEYBYTESObject, *PUBLICKEYBYTESObject, *SIGNATUREBYTESObject;
/* --------------------------------------------------------------------- */

#include "crypto_sign.h"

PyDoc_STRVAR(ed25519_publickey_doc,
"publickey(signkey_seed)\n\
\n\
Accepts a 32-byte seed. Return a tuple of (verfkey, signkey), with the\n\
64-byte private signing key and the corresponding 32-byte public\n\
verfiying key.");

#include <stdio.h>

static PyObject *
ed25519_publickey(PyObject *self, PyObject *args)
{
    unsigned char verfkey[PUBLICKEYBYTES];
    unsigned char signkey[SECRETKEYBYTES];
    unsigned char *seed;
    unsigned int seed_len;
    if (!PyArg_ParseTuple(args, "s#", &seed, &seed_len))
        return NULL;
    crypto_sign_publickey(verfkey, signkey, seed);
    return Py_BuildValue("(s#s#)",
                         verfkey, PUBLICKEYBYTES,
                         signkey, SECRETKEYBYTES);
}

PyDoc_STRVAR(ed25519_sign_doc,
"sign(message, signing_key)\n\
\n\
Return the concatenation of three parts: the 32-byte R signature value,\n\
the original message, and the 32-byte S signature value.");

static PyObject *
ed25519_sign(PyObject *self, PyObject *args)
{
    const unsigned char *msg; Py_ssize_t msg_len;
    const unsigned char *signkey; Py_ssize_t signkey_len;
    unsigned char *sig_and_msg; unsigned long long sig_and_msg_len1;
    Py_ssize_t sig_and_msg_len2;
    PyObject *ret;

    // NOTE: using s# copies the message. It'd be nicer to use it in-place.
    // Consider s* and using a Py_buffer. Don't forget PyBuffer_Release.
    // Py_buffer is available in py2.6 and later.
    //// on the other hand, the funky NaCl API means we're already doing 3
    //// copies anyway, so a 4th isn't a big deal.
    if (!PyArg_ParseTuple(args, "s#s#:signature",
                          &msg, &msg_len,
                          &signkey, &signkey_len))
        return NULL;
    if (signkey_len != SECRETKEYBYTES) { // 64
        PyErr_SetString(PyExc_TypeError,
                        "Private signing keys are 64 byte strings");
        return NULL;
    }
    sig_and_msg = PyMem_Malloc(msg_len + SIGNATUREBYTES);
    if (!sig_and_msg)
        return PyErr_NoMemory();
    crypto_sign(sig_and_msg, &sig_and_msg_len1, msg, msg_len, signkey);
    sig_and_msg_len2 = sig_and_msg_len1;
    ret = Py_BuildValue("s#", sig_and_msg, sig_and_msg_len2);
    PyMem_Free(sig_and_msg);
    return ret;
}

PyDoc_STRVAR(ed25519_open_doc,
"open(message+signature, verifying_key)\n\
\n\
Check the signature for validity. Returns the message if valid, raises\n\
ed25519.error if not.");

static PyObject *
ed25519_open(PyObject *self, PyObject *args)
{
    const unsigned char *sig_and_msg; Py_ssize_t sig_and_msg_len;
    const unsigned char *verfkey; Py_ssize_t verfkey_len;
    unsigned char *msg; unsigned long long msg_len1;
    Py_ssize_t msg_len2;
    PyObject *ret;
    int result;
    if (!PyArg_ParseTuple(args, "s#s#:checkvalid",
                          &sig_and_msg, &sig_and_msg_len,
                          &verfkey, &verfkey_len ))
        return NULL;
    if (sig_and_msg_len < SIGNATUREBYTES) { // 64
        PyErr_SetString(PyExc_TypeError,
                        "signature-and-message must be at least 64 bytes long");
        return NULL;
    }
    if (verfkey_len != PUBLICKEYBYTES) { // 32
        PyErr_SetString(PyExc_TypeError,
                        "Public verifying keys are 32 byte strings");
        return NULL;
    }

    // crypto_sign_open() uses the output buffer as a scratchpad, and thus
    // requires an extra 64 bytes beyond the expected message. So allocate
    // sig_and_msg_len, not sig_and_msg_len-SIGNATUREBYTES
    msg = PyMem_Malloc(sig_and_msg_len);
    if (!msg)
        return PyErr_NoMemory();
    result = crypto_sign_open(msg, &msg_len1, sig_and_msg, sig_and_msg_len,
                              verfkey);
    // be faithful to the NaCl interface and return the message, even though
    // it's a waste.
    if (result == 0) {
        // good signature
        msg_len2 = msg_len1;
        ret = Py_BuildValue("s#", msg, msg_len2);
        PyMem_Free(msg);
        return ret;
    }
    // bad signature. We do throw an exception when the signature is bad, so
    // it can't be silently ignored
    PyMem_Free(msg);
    PyErr_SetString(BadSignatureError, "Bad Signature");
    return NULL;
}


/* List of functions defined in the module */

static PyMethodDef ed25519_methods[] = {
    {"publickey",  ed25519_publickey,  METH_VARARGS, ed25519_publickey_doc},
    {"sign",  ed25519_sign,  METH_VARARGS, ed25519_sign_doc},
    {"open", ed25519_open, METH_VARARGS, ed25519_open_doc},
    {NULL, NULL} /* sentinel */
};

PyDoc_STRVAR(module_doc,
"Low-level Ed25519 signature/verification functions.");

/* Initialization function for the module (*must* be called init_ed25519) */

PyMODINIT_FUNC
init_ed25519(void)
{
    PyObject *m;

    /* Create the module and add the functions */
    m = Py_InitModule3("_ed25519", ed25519_methods, module_doc);
    if (m == NULL)
        return;

    /* Add some symbolic constants to the module */
    if (BadSignatureError == NULL) {
        BadSignatureError = PyErr_NewException("ed25519.BadSignatureError",
                                               NULL, NULL);
        if (BadSignatureError == NULL)
            return;
    }
    if (SECRETKEYBYTESObject == NULL) {
        SECRETKEYBYTESObject = PyInt_FromLong(SECRETKEYBYTES);
        if (SECRETKEYBYTESObject == NULL)
            return;
    }
    if (PUBLICKEYBYTESObject == NULL) {
        PUBLICKEYBYTESObject = PyInt_FromLong(PUBLICKEYBYTES);
        if (PUBLICKEYBYTESObject == NULL)
            return;
    }
    if (SIGNATUREBYTESObject == NULL) {
        SIGNATUREBYTESObject = PyInt_FromLong(SIGNATUREBYTES);
        if (SIGNATUREBYTESObject == NULL)
            return;
    }
    Py_INCREF(BadSignatureError);
    PyModule_AddObject(m, "BadSignatureError", BadSignatureError);
    PyModule_AddObject(m, "SECRETKEYBYTES", SECRETKEYBYTESObject);
    PyModule_AddObject(m, "PUBLICKEYBYTES", PUBLICKEYBYTESObject);
    PyModule_AddObject(m, "SIGNATUREKEYBYTES", SIGNATUREBYTESObject);
}
