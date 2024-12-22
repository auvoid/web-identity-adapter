import {
  CreateDidProps,
  CredentialsManager,
  DidCreationResult,
  DidSigner,
  IdentityAccount,
  IdentityAccountProps,
  IdentityConfig,
  NetworkAdapter,
  NetworkAdapterOptions,
  StorageSpec,
  bytesToString,
  stringToBytes,
} from "@tanglelabs/ssimon";
import nacl from "tweetnacl";

import * as didJWT from "did-jwt";
// @ts-ignore
import { Ed25519VerificationKey2018 } from "@digitalbazaar/ed25519-verification-key-2018";
import { Resolver } from "did-resolver";

export class DidWebAdapter implements NetworkAdapter {
  store: StorageSpec<any, any>;
  resolver: Resolver;
  private constructor() {}

  public async buildDidAccount(
    props: IdentityAccountProps<any>
  ): Promise<IdentityAccount> {
    const { seed, store, alias } = props;

    const keyPair = nacl.box.keyPair.fromSecretKey(stringToBytes(seed));

    const account = new IdentityAccount();
    const key =
      bytesToString(keyPair.secretKey) + bytesToString(keyPair.publicKey);
    const keyUint8Array = stringToBytes(key);

    const { publicKeyBase58 } = await Ed25519VerificationKey2018.generate({
      seed: stringToBytes(seed),
    });

    const didUrl = "did:web:" + alias;
    const keyUrl = didUrl + "#key-0";
    const verificationMethod = {
      id: keyUrl,
      type: "Ed25519VerificationKey2018",
      controller: didUrl,
      publicKeyBase58,
    };
    const signer = didJWT.EdDSASigner(keyUint8Array);
    const didSigner: DidSigner = {
      did: didUrl as `did:${string}`,
      kid: (didUrl + "#key-0") as `did:${string}`,
      signer,
      alg: "EdDSA",
    };

    console.log(this.resolver);
    const credentials = CredentialsManager.build(
      store,
      didSigner,
      this.resolver
    );

    account.signer = didSigner;
    account.document = {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: didUrl,
      verificationMethod: [verificationMethod],
      authentication: [keyUrl],
      assertionMethod: [keyUrl],
      keyAgreement: [keyUrl],
    };
    account.credentials = credentials;

    return account;
  }

  /**
   * Create a new instance of network adapter
   *
   * @param {NetworkAdapterOptions} options
   * @returns {Promise<DidKeyAdapter>}
   */

  public static async build(
    options: NetworkAdapterOptions
  ): Promise<DidWebAdapter> {
    const adapter = new DidWebAdapter();
    adapter.store = options.driver;
    adapter.resolver = options.resolver;
    return adapter;
  }

  getMethodIdentifier() {
    return "web";
  }

  /**
   * Create a new DID and store in the store defined with the adapter
   *
   * @param {CreateDidProps} props
   * @returns {Promise<DidCreationResult>}
   */
  async createDid(props: CreateDidProps): Promise<DidCreationResult> {
    const { seed, alias, store } = props;

    const hostnameRegex = /^(?!:\/\/)([a-zA-Z0-9-]{1,63}\.?)+[a-zA-Z]{2,}$/;

    const validAlias = hostnameRegex.test(alias);
    if (!validAlias)
      throw new Error("Alias must be a domain, example `domain.com`");

    const generatedKeyPair = nacl.box.keyPair();
    const generatedSeed = bytesToString(generatedKeyPair.secretKey);

    const identity = await this.buildDidAccount({
      seed: seed ?? generatedSeed,
      isOld: !!seed,
      alias,
      store,
    });

    console.log(identity);
    return { identity, seed: seed ?? generatedSeed };
  }

  /**
   * Deserialize a DID and return the DID config result
   *
   * @param {IdentityConfig} config
   * @param {T} store
   * @returns {Promise<DidCreationResult>}
   */
  async deserializeDid<T extends StorageSpec<Record<string, any>, any>>(
    config: IdentityConfig,
    store: T
  ): Promise<DidCreationResult> {
    const identity = await this.buildDidAccount({
      seed: config.seed as string,
      isOld: true,
      alias: config.alias,
      store: store,
    });
    return { identity, seed: config.seed as string };
  }
}
