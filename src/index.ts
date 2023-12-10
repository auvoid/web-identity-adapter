import {
    CreateCredentialProps,
    CreateBadgeProps,
    CreateDidProps,
    CredentialsManager,
    DidCreationResult,
    IVerificationResult,
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
import { DID } from "dids";
import { Ed25519Provider } from "key-did-provider-ed25519";
import {
    JwtCredentialPayload,
    createVerifiableCredentialJwt,
    JwtPresentationPayload,
    createVerifiablePresentationJwt,
    verifyCredential,
} from "did-jwt-vc";
import * as didJWT from "did-jwt";
import * as KeyResolver from "key-did-resolver";
import { Resolver } from "did-resolver";
import { Validator } from "jsonschema";
import { OpenBadgeSchema } from "./ob-schema";

export class DidWebAdapter implements NetworkAdapter {
    store: StorageSpec<any, any>;
    private constructor() {}

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
        return adapter;
    }

    /**
     * Create a new DID and store in the store defined with the adapter
     *
     * @param {CreateDidProps} props
     * @returns {Promise<DidCreationResult>}
     */
    async createDid<T extends StorageSpec<Record<string, any>, any>>(
        props: CreateDidProps<T>
    ): Promise<DidCreationResult> {
        const { seed, alias, store } = props;

        const generatedKeyPair = nacl.box.keyPair();
        const generatedSeed = bytesToString(generatedKeyPair.secretKey);
        console.log(seed ?? generatedSeed);

        const identity = await DidWebAccount.build({
            seed: seed ?? generatedSeed,
            isOld: !!seed,
            alias,
            store,
        });

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
        const identity = await DidWebAccount.build({
            seed: config.seed as string,
            isOld: true,
            alias: config.alias,
            store: store,
        });
        return { identity, seed: config.seed as string };
    }
}

export class DidWebAccount implements IdentityAccount {
    credentials: CredentialsManager<StorageSpec<Record<string, any>, any>>;
    document: Record<string, any>;
    keyPair: nacl.BoxKeyPair;

    /**
     * Create a new DID Account class
     *
     * @param {IdentityAccountProps} props
     * @returns {Promise<DidWebAccount>}
     */
    public static async build(
        props: IdentityAccountProps<any>
    ): Promise<DidWebAccount> {
        const { seed, store } = props;

        console.log(seed);
        const keyPair = nacl.box.keyPair.fromSecretKey(stringToBytes(seed));
        const provider = new Ed25519Provider(stringToBytes(seed));

        const account = new DidWebAccount();
        const credentials = await DidKeyCredentialsManager.build(
            store,
            account
        );
        account.keyPair = keyPair;
        const did = new DID({
            provider,
            resolver: KeyResolver.getResolver(),
        });
        console.log(await did.());

        account.credentials = credentials;

        return account;
    }

    /**
     * Get back the did string
     *
     * @returns {string}
     */
    getDid(): string {
        return this.document.id;
    }

    /**
     * Get back the did document
     *
     * @returns {Record<string, any>}
     */
    async getDocument(): Promise<Record<string, any>> {
        return this.document;
    }

    /**
     * Create a verifiable presentation
     *
     * @param {string[]} credentials
     * @returns {Promise<{ vpPayload: Record<string, any>; presentationJwt: string }>}
     */
    async createPresentation(
        credentials: string[]
    ): Promise<{ vpPayload: Record<string, any>; presentationJwt: string }> {
        const key =
            bytesToString(this.keyPair.secretKey) +
            bytesToString(this.keyPair.publicKey);
        const keyUint8Array = stringToBytes(key);

        const signer = didJWT.EdDSASigner(keyUint8Array);
        const vpIssuer = {
            did: this.getDid(),
            signer,
            alg: "EdDSA",
        };

        const vpPayload: JwtPresentationPayload = {
            vp: {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiablePresentation"],
                verifiableCredential: credentials,
            },
        };

        const presentationJwt = await createVerifiablePresentationJwt(
            vpPayload,
            vpIssuer
        );

        return { vpPayload, presentationJwt };
    }
}

export class DidKeyCredentialsManager<
    T extends StorageSpec<Record<string, any>, any>
> implements CredentialsManager<T>
{
    store: T;
    account: DidWebAccount;

    private constructor() {}

    /**
     * Create a new instance o DidKeyCredentialsManager
     *
     * @param {T} store
     * @param {DidWebAccount} account
     * @returns
     */
    public static async build<T extends StorageSpec<Record<string, any>, any>>(
        store: T,
        account: DidWebAccount
    ) {
        const credentialsManager = new DidKeyCredentialsManager();
        credentialsManager.store = store;
        credentialsManager.account = account;
        return credentialsManager;
    }

    /**
     * Check if the credential is valid, sans DVID Proof
     *
     * @param {{ cred: string }} credential
     * @returns {Promise<boolean>}
     */
    async isCredentialValid(
        credential: Record<string, unknown>
    ): Promise<boolean> {
        const result = await this.verify(credential);
        return result.vc;
    }

    /**
     * Check if the credential is valid
     *
     * @param {{ cred: string }} credential
     * @returns {Promise<IVerificationResult>}
     */
    async verify(
        credential: Record<string, unknown>
    ): Promise<IVerificationResult> {
        const { cred } = credential;
        const keyDIDResolver = KeyResolver.getResolver();
        const didResolver = new Resolver(keyDIDResolver);
        await verifyCredential(cred as string, didResolver);
        return { vc: true, dvid: true };
    }

    /**
     * Create a new credential to issue
     *
     * @param {CreateCredentialProps} options
     * @returns {Promise<Record<string, any>>}
     */
    async create(options: CreateCredentialProps): Promise<Record<string, any>> {
        const { id, recipientDid, body, type } = options;

        const key =
            bytesToString(this.account.keyPair.secretKey) +
            bytesToString(this.account.keyPair.publicKey);
        const keyUint8Array = stringToBytes(key);

        const signer = didJWT.EdDSASigner(keyUint8Array);
        const didId =
            this.account.getDid() +
            "#" +
            this.account.getDid().split("did:key:")[1];
        const vcIssuer = {
            did: didId,
            signer,
            alg: "EdDSA",
        };
        const types = Array.isArray(type) ? [...type] : [type];

        const credential: JwtCredentialPayload = {
            sub: recipientDid,
            nbf: Math.floor(Date.now() / 1000),
            id,
            vc: {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiableCredential", ...types],
                id,
                credentialSubject: {
                    ...body,
                },
            },
        };
        const jwt = await createVerifiableCredentialJwt(credential, vcIssuer);

        return { cred: jwt };
    }

    async createBadge(options: CreateBadgeProps) {
        const {
            id,
            recipientDid,
            body,
            type,
            image,
            issuerName,
            criteria,
            description,
        } = options;

        const key =
            bytesToString(this.account.keyPair.secretKey) +
            bytesToString(this.account.keyPair.publicKey);
        const keyUint8Array = stringToBytes(key);

        const signer = didJWT.EdDSASigner(keyUint8Array);
        const didId =
            this.account.getDid() +
            "#" +
            this.account.getDid().split("did:key:")[1];
        const vcIssuer = {
            did: didId,
            signer,
            alg: "EdDSA",
        };
        const types = Array.isArray(type) ? [...type] : [type];
        const credential: JwtCredentialPayload = {
            sub: recipientDid,
            nbf: Math.floor(Date.now() / 1000),
            id,
            vc: {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json",
                ],
                type: ["VerifiableCredential", "OpenBadgeCredential"],
                id,
                name: type,
                issuer: {
                    id: new URL("/", id).toString(),
                    type: ["Profile"],
                    name: issuerName,
                },
                issuanceDate: new Date(Date.now()).toISOString(),
                credentialSubject: {
                    type: ["AchievementSubject"],
                    achievement: {
                        id: id,
                        type: "",
                        criteria: {
                            narrative: criteria,
                        },
                        name: type,
                        description: description,
                        image: {
                            id: image,
                            type: "Image",
                        },
                        ...body,
                    },
                },
            },
        };

        const validator = new Validator();
        const result = validator.validate(credential.vc, OpenBadgeSchema);
        if (result.errors.length > 0)
            throw new Error("Schema Validation Failed");
        const jwt = await createVerifiableCredentialJwt(credential, vcIssuer);

        return { cred: jwt };
    }

    revoke(keyIndex: number): Promise<void> {
        throw new Error("Method not implemented.");
    }
}
