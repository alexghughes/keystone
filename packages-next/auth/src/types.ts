import { BaseGeneratedListTypes, KeystoneAdminConfig, KeystoneConfig, FieldType } from '@keystone-spike/types';

export type SendTokenFn = (args: {
  itemId: string | number;
  identity: string;
  token: string;
}) => Promise<void> | void;

export type AuthGqlNames = {
  /** Change the name of the authenticate{listKey}WithPassword mutation */
  authenticateItemWithPassword?: string;
  /** Change the name of the send{listKey}PasswordResetLink mutation */
  sendItemPasswordResetLink?: string;
  /** Change the name of the send{listKey}MagicAuthLink mutation */
  sendItemMagicAuthLink?: string;
  /** Change the name of the createInitial{listKey} mutation */
  createInitialItem?: string;
};

export type ResolvedAuthGqlNames = Required<AuthGqlNames> & {
  ItemAuthenticationWithPasswordResult: string;
  ItemAuthenticationWithPasswordSuccess: string;
  ItemAuthenticationWithPasswordFailure: string;
  sendItemPasswordResetLinkResult: string;
  sendItemMagicAuthLinkResult: string;
};

export type AuthConfig<GeneratedListTypes extends BaseGeneratedListTypes> = {
  /** The key of the list to authenticate users with */
  listKey: GeneratedListTypes['key'];
  /** The path of the field the identity is stored in; must be text-ish */
  identityField: GeneratedListTypes['fields'];
  /** The path of the field the secret is stored in; must be password-ish */
  secretField: GeneratedListTypes['fields'];

  // Attempts to prevent consumers of the API from being able to determine the value of identity fields
  protectIdentities?: boolean;

  passwordResetLink?: {
    /** Called when a user should be sent the forgotten password token they requested */
    sendToken: SendTokenFn;
    /** How long do tokens stay valid for from time of issue, in minutes **/
    tokensValidForMins: number;
  };
  magicAuthLink?: {
    /** Called when a user should be sent the magic signin token they requested */
    sendToken: SendTokenFn;
    /** How long do tokens stay valid for from time of issue, in minutes **/
    tokensValidForMins: number;
  };
  initFirstItem?: {
    /** Array of fields to collect, e.g ['name', 'email', 'password'] */
    fields: GeneratedListTypes['fields'][];
    /** Suppresses the second screen where we ask people to subscribe and follow Keystone */
    skipKeystoneSignup?: boolean;
    /** Extra input to add for the create mutation */
    itemData?: Partial<GeneratedListTypes['inputs']['create']>;
  };
};

export type Auth = {
  admin: {
    enableSessionItem: NonNullable<KeystoneAdminConfig['enableSessionItem']>;
    publicPages: NonNullable<KeystoneAdminConfig['publicPages']>;
    pageMiddleware: NonNullable<KeystoneAdminConfig['pageMiddleware']>;
    getAdditionalFiles: NonNullable<KeystoneAdminConfig['getAdditionalFiles']>[number];
  };
  extendGraphqlSchema: NonNullable<KeystoneConfig['extendGraphqlSchema']>;
  fields: { [prop: string]: FieldType };
  validateConfig: (keystoneConfig: KeystoneConfig) => void;
  withAuth: (config: KeystoneConfig) => KeystoneConfig;
};

export enum AuthErrorCode {

  // Password authentication
  PASSWORD_AUTH_FAILURE, // Generic
  PASSWORD_AUTH_IDENTITY_NOT_FOUND,
  PASSWORD_AUTH_SECRET_NOT_SET,
  PASSWORD_AUTH_MULTIPLE_IDENTITY_MATCHES,
  PASSWORD_AUTH_SECRET_MISMATCH,

  // Password resets and magic links
  AUTH_TOKEN_REQUEST_IDENTITY_NOT_FOUND,
  AUTH_TOKEN_REQUEST_MULTIPLE_IDENTITY_MATCHES,
  AUTH_TOKEN_REDEMPTION_INVALID_TOKEN,
  AUTH_TOKEN_REDEMPTION_TOKEN_EXPIRED,
  AUTH_TOKEN_REDEMPTION_TOKEN_REDEEMED,
  AUTH_TOKEN_INTERNAL_ERROR,

  // Not used by the auth package itself
  // Allows custom logic/errors to be generated without replacing the gql output types
  CUSTOM_ERROR,
};
