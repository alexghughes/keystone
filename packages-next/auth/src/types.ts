import { BaseGeneratedListTypes, KeystoneAdminConfig, KeystoneConfig } from '@keystone-spike/types';

export type SendTokenFn = (args: {
  // TODO: should we know, through config, how to generate a fully-qualified URL? how are we
  // handling the protocol/server/port that the app is hosted on?
  // JM: ^^^ Pretty sure, not?
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

  // Query and mutation names to use
  gqlNames?: AuthGqlNames;

  passwordResetLink?: {
    /** Called when a user should be sent the forgotten password token they requested */
    sendToken: SendTokenFn;
  };
  magicAuthLink?: {
    /** Called when a user should be sent the magic signin token they requested */
    sendToken: SendTokenFn;
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
  lists?: KeystoneConfig['lists'];
  validateConfig: (keystoneConfig: KeystoneConfig) => void;
  withAuth: (config: KeystoneConfig) => KeystoneConfig;
};
