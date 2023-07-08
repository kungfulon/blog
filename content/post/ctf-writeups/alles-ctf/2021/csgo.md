---
title: "ALLES! CTF 2021 - 🔥 Counter Strike: Squirrel Offensive"
date: 2021-09-06T07:30:12Z
draft: false
tags:
  - source-engine
  - ctf
  - pwn
---

This challenge involves an old version of CS:GO VScript, which is vulnerable to [a UAF bug and a type confusion bug](https://github.com/albertodemichelis/squirrel/issues/220).

Resources on VScript can be found [here](https://developer.valvesoftware.com/wiki/VScript).

[Here](https://gist.githubusercontent.com/kungfulon/c50323cf6ae54104e3c65b2b30804cc1/raw/c2f6cf5a5eabea14c40ef152c83c6fff1ba5e894/exp.nut) is the exploit script.

## UAF by resizing array in sort compare function

The sort function of squirrel array is `array_sort` in `sqbaselib.cpp`, which will call `_qsort`:

```cpp
// v: VM, o: array object, func: compare func
_qsort(v, o, 0, _array(o)->Size()-1, func);
```

The `r` index passed into `_qsort` is fixed at the beginning, so by abusing `array.resize` in compare function, we can retrieve dangling reference to freed objects through compare function parameters.

By freeing a string then overlap it with an array, the `_len` field of the freed `SQString` object will be overwritten by the `_sharedstate` field of the newly created `SQArray`. It's a pointer so the value will be very large, and we can use the dangling string to do arbitrary reading over a large heap space after it.

## Type confusion in regexp functions

`_regexp_*` functions in `sqstdstring.cpp` retrieve `SQRex` object from the current object using `SETUP_REX` macro:

```cpp
#define SETUP_REX(v) \
    SQRex *self = NULL; \
    sq_getinstanceup(v,1,(SQUserPointer *)&self,0); 
```

The `typetag` parameter is `0`, means that it will not check for type mismatch. So we can call `_regexp_*` functions using any `instance` object (examples: self-defined classes, external library classes like CS:GO script classes).

## Addresses leaking

As we have a long string by using UAF bug above, we can just spray a lot of `CScriptKeyValues` and find one of them using last 2 bytes of `SQInstance::vtable` as they will not be affected by Windows ASLR, then use confusion to watch for changes to `_userpointer` field. But there are other `instance` objects too, and we have no way to be sure that it's a `CScriptKeyValues` object.

Fortunately, the `tostring` method will return the type name and the address in memory of any object. For number and string it will just return the value. But we overlapped the freed string with an array, so we can get address of it by calling `tostring` on the array. We can keep allocate new `CScriptKeyValues` object until we get one that lies after our long string and in the range that we can read its data. I won't go into detail of Source Engine heap in this writeup, but most of the time we will get a satisfied object without triggering Squirrel timeout watchdog.

By reading the `CScriptKeyValues` object, we can get these values:

- Pointer to `SQInstance::vtable`, which can be used to calculate `vscript.dll` base address for ROP gadgets
- Pointer to `_userpointer` of that object

## Path of exploitation

My approach is to use a CS:GO script class, `CScriptKeyValues`. Squirrel will panic if you attempt to modify the prototype after 1 instance of a class has been created. Since in map loading, there're no instance of this class would be created, we can modify its prototype:

```js
CScriptKeyValues.confuse <- regexp.constructor;
CScriptKeyValues.confuse2 <- regexp.search;
```

When we call any method of a CS:GO script class, `CSquirrelVM::TranslateCall` in `vsquirrel.cpp` will be called. It will access `_userpointer` field of the object to get binding information:

```cpp
pContext = (InstanceContext_t *)sa.GetInstanceUp(1,0); // _userpointer

if ( !pContext )
{
    sq_throwerror( hVM, "Accessed null instance" );
    return SQ_ERROR;
}

pObject = pContext->pInstance;

if ( !pObject )
{
    sq_throwerror( hVM, "Accessed null instance" );
    return SQ_ERROR;
}

if ( pContext->pClassDesc->pHelper )
{
    pObject = pContext->pClassDesc->pHelper->GetProxied( pObject );
}
```

`_regexp_constructor` will create a new `SQRex` class and store it in `_userpointer` field. That means we can control `pContext`. Below is `InstanceContext_t` struct:

```cpp
struct InstanceContext_t
{
    void *pInstance;
    ScriptClassDesc_t *pClassDesc;
    SQObjectPtr name;
};
```

Below is `SQRex` struct:

```cpp
struct SQRex{
    const SQChar *_eol;
    const SQChar *_bol;
    const SQChar *_p;
    SQInteger _first;
    SQInteger _op;
    SQRexNode *_nodes;
    SQInteger _nallocated;
    SQInteger _nsize;
    SQInteger _nsubexpr;
    SQRexMatch *_matches;
    SQInteger _currsubexp;
    void *_jmpbuf;
    const SQChar **_error;
};
```

`pClassDesc` field overlaps with `_bol` field. When we call `_regexp_search(str)`, `_bol` field will be set to the beginning of `str`. So we can craft a fake `ScriptClassDesc_t` object using a string. Below is `ScriptClassDesc_t` struct:

```cpp
struct ScriptClassDesc_t
{
    const char *                        m_pszScriptName;
    const char *                        m_pszClassname;
    const char *                        m_pszDescription;
    ScriptClassDesc_t *                    m_pBaseDesc;
    CUtlVector<ScriptFunctionBinding_t> m_FunctionBindings;

    void *(*m_pfnConstruct)();
    void (*m_pfnDestruct)( void *);
    IScriptInstanceHelper *                pHelper; // offset 0x2C

    ScriptClassDesc_t *                    m_pNextDesc;
};
```

Below is `IScriptInstanceHelper` interface:

```cpp
class IScriptInstanceHelper
{
public:
    virtual void *GetProxied( void *p );
    virtual bool ToString( void *p, char *pBuf, int bufSize );
    virtual void *BindOnRead( HSCRIPT hInstance, void *pOld, const char *pszId );
};
```

We can craft a fake `IScriptInstanceHelper` object to control the virtual method table.

Fortunately, Squirrel string is not null-terminated, so we don't have to worry about null bytes.

In conclusion, the fake object will look like this:

| Offset | Content                       |
|--------|-------------------------------|
| 0x0    | pivot gadget                  |
| ...    | padding                       |
| 0x2C   | `_userpointer + 0x4` (`_bol`) |

## Conclusion

Thanks ALLES! team for organizing a great CTF with awesome challenges, and allowed late submission of 🔥 challenges.

Source Engine is a mature engine with a lot of functions, and use a lot of unsafe memory code. With the fact that any people can host dedicated servers, it's a huge attack surface. It's sad that Valve never bothers fixing security bugs in the engine quickly. I really hoped that they will pick up the pace after secret club's callout, but seems like they will never do that.
