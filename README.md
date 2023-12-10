# DID Web Adapter

`did:web` adapter for `@tanglelabs/ssimon`

## Installation

### 1. npm

```sh
$ npm install @tanglelabs/ssimon @tanglelabs/web-identity-adapter
```

### 2. yarn

```sh
$ yarn add @tanglelabs/ssimon @tanglelabs/web-identity-adapter
```

## Usage

```ts
(async () => {
    const manager = await IdentityManager.build({
        adapter: DidWebAdapter,
        storage,
    });

    const did = await manager.createDid({
        alias: "domain.com",
        store,
    });

    console.log(did.getDid());
})();
```

### Result

```
did:web:domain.com
```
