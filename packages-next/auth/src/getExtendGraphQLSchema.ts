import { graphQLSchemaExtension } from '@keystone-spike/keystone/schema';
import { ResolvedAuthGqlNames, SendTokenFn, AuthErrorCode } from './types';
import { randomBytes } from 'crypto';

const generateToken = function (length: number): string {
  return randomBytes(length)
    .toString('base64')
    .slice(0, length)
    .replace(/[^a-zA-Z0-9]/g, '');
};

const getErrorMessage = function (identityField: string, secretField: string, itemSingular: string, itemPlural: string, code: AuthErrorCode): string {
  switch (code) {
    case AuthErrorCode.PASSWORD_AUTH_FAILURE: return 'Authentication failed';
    case AuthErrorCode.PASSWORD_AUTH_IDENTITY_NOT_FOUND: return `The ${identityField} value provided didn't identify any ${itemPlural}`;
    case AuthErrorCode.PASSWORD_AUTH_SECRET_NOT_SET: return `The ${itemSingular} identified has no ${secretField} set so can not be authenticated`;
    case AuthErrorCode.PASSWORD_AUTH_MULTIPLE_IDENTITY_MATCHES: return `The ${identityField} value provided identified more than one ${itemSingular}`;
    case AuthErrorCode.PASSWORD_AUTH_SECRET_MISMATCH: return `The ${secretField} provided is incorrect`;
    case AuthErrorCode.AUTH_TOKEN_REQUEST_IDENTITY_NOT_FOUND: return `The ${identityField} value provided didn't identify any ${itemPlural}`;
    case AuthErrorCode.AUTH_TOKEN_REQUEST_MULTIPLE_IDENTITY_MATCHES: return `The ${identityField} value provided identified more than one ${itemSingular}`;
    case AuthErrorCode.AUTH_TOKEN_REDEMPTION_INVALID_TOKEN: return 'The token provided is invalid';
    case AuthErrorCode.AUTH_TOKEN_REDEMPTION_TOKEN_EXPIRED: return 'The token provided has expired';
    case AuthErrorCode.AUTH_TOKEN_REDEMPTION_TOKEN_REDEEMED: return 'The token provided has already been redeemed';
    case AuthErrorCode.AUTH_TOKEN_INTERNAL_ERROR: return `An unexpected error condition was encountered while creating or redeeming an auth token`;
  }
  return 'No error message defined';
}

export function getExtendGraphQLSchema({
  listKey,
  identityField,
  secretField,
  protectIdentities,
  gqlNames,
  passwordResetLink,
  magicAuthLink: { sendToken: sendMagicAuthLink } = { sendToken: () => {} },
}: {
  listKey: string;
  identityField: string;
  secretField: string;
  protectIdentities: boolean;
  gqlNames: ResolvedAuthGqlNames;
  passwordResetLink?: { sendToken: SendTokenFn };
  magicAuthLink?: { sendToken: SendTokenFn };
}) {

  async function attemptAuthentication(
    args: Record<string, string>,
    list: any
  ): Promise<
    | {
        success: false;
        code: AuthErrorCode;
      }
    | {
        success: true;
        item: { id: any; [prop: string]: any };
  }
  > {
    const identity = args[identityField];
    const canidatePlaintext = args[secretField];
    const secretFieldInstance = list.fieldsByPath[secretField];

    // TODO: Allow additional filters to be suppled in config? eg. `validUserConditions: { isEnable: true, isVerified: true, ... }`
    // TODO: Maybe talk to the list rather than the adapter? (Might not validate the filters though)
    const items = await list.adapter.find({ [identityField]: identity });

    // Identity failures with helpful errors
    let specificCode: AuthErrorCode | undefined;
    if (items.length === 0) {
      specificCode = AuthErrorCode.PASSWORD_AUTH_IDENTITY_NOT_FOUND;
    } else if (items.length === 1 && !items[0][secretField]) {
      specificCode = AuthErrorCode.PASSWORD_AUTH_SECRET_NOT_SET;
    } else if (items.length > 1) {
      specificCode = AuthErrorCode.PASSWORD_AUTH_MULTIPLE_IDENTITY_MATCHES;
    }
    if (typeof specificCode !== 'undefined') {
      // If we're trying to maintain the privacy of accounts (hopefully, yes) make some effort to prevent timing attacks
      // Note, we're not attempting to protect the hashing comparisson itself from timing attacks, just _the existance of an item_
      // We can't assume the work factor so can't include a pre-generated hash to compare but generating a new hash will create a similar delay
      // Changes to the work factor, latency loading the item(s) and many other factors will still be detectable by a dedicated attacker
      // This is far from perfect (but better than nothing)
      protectIdentities &&
        (await secretFieldInstance.generateHash('simulated-password-to-counter-timing-attack'));
      return { success: false, code: protectIdentities ? AuthErrorCode.PASSWORD_AUTH_FAILURE : specificCode };
    }

    const item = items[0];
    const isMatch = await secretFieldInstance.compare(canidatePlaintext, item[secretField]);
    if (!isMatch) {
      specificCode = AuthErrorCode.PASSWORD_AUTH_SECRET_MISMATCH;
      return { success: false, code: protectIdentities ? AuthErrorCode.PASSWORD_AUTH_FAILURE : specificCode };
    }

    // Authenticated!
    return { success: true, item };
  }

  // TODO: Auth token mutations may leak user identities due to timing attacks :(
  // We don't (currently) make any effort to mitigate the time taken to record the new token or sent the email when successful
  async function updateAuthToken(
    tokenType: string,
    identity: string,
    list: any,
    ctx: any
  ): Promise<
    | {
        success: false;
        code?: AuthErrorCode;
      }
    | {
        success: true;
        itemId: string | number;
        token: string;
      }
  > {
    const items = await list.adapter.find({ [identityField]: identity });

    // Identity failures with helpful errors (unless it would violate our protectIdentities config)
    let specificCode: AuthErrorCode | undefined;
    if (items.length === 0) {
      specificCode = AuthErrorCode.AUTH_TOKEN_REQUEST_IDENTITY_NOT_FOUND;
    } else if (items.length > 1) {
      specificCode = AuthErrorCode.AUTH_TOKEN_REQUEST_MULTIPLE_IDENTITY_MATCHES;
    }
    if (typeof specificCode !== 'undefined') {
      return { success: false, code: protectIdentities ? undefined : specificCode };
    }

    const item = items[0];
    const token = generateToken(20);

    // Save the token and related info back to the item
    const { errors } = await ctx.keystone.executeGraphQL({
      context: ctx.keystone.createContext({ skipAccessControl: true }),
      query: `mutation($id: String, $token: String, $now: String) {
        updateUser(id: $id, data: {
          ${tokenType}Token: $token,
          ${tokenType}IssuedAt: $now,
          ${tokenType}RedeemedAt: null
        }) { id }
      }`,
      variables: { id: item.id, token, now: new Date().toISOString() },
    });
    if (Array.isArray(errors) && errors.length > 0) {
      console.error(errors[0] && (errors[0].stack || errors[0].message));
      return { success: false, code: AuthErrorCode.AUTH_TOKEN_INTERNAL_ERROR };
    }

    return { success: true, itemId: item.id, token };
  }

  return graphQLSchemaExtension({
    typeDefs: `
      union AuthenticatedItem = ${listKey}
      type Query {
        authenticatedItem: AuthenticatedItem
      }

      type Mutation {
        ${gqlNames.authenticateItemWithPassword}(${identityField}: String!, ${secretField}: String!):
        ${gqlNames.ItemAuthenticationWithPasswordResult}!
      }
      union ${gqlNames.ItemAuthenticationWithPasswordResult} = ${gqlNames.ItemAuthenticationWithPasswordSuccess} | ${gqlNames.ItemAuthenticationWithPasswordFailure}
      type ${gqlNames.ItemAuthenticationWithPasswordSuccess} {
        token: String!
        item: ${listKey}!
      }
      type ${gqlNames.ItemAuthenticationWithPasswordFailure} {
        code: AuthErrorCode!
        message: String!
      }

      type Mutation {
        ${gqlNames.sendItemPasswordResetLink}(${identityField}: String!): ${gqlNames.sendItemPasswordResetLinkResult}!
      }
      type ${gqlNames.sendItemPasswordResetLinkResult} {
        code: AuthErrorCode
        message: String
      }

      type Mutation {
        ${gqlNames.sendItemMagicAuthLink}(${identityField}: String!): ${gqlNames.sendItemMagicAuthLinkResult}!
      }
      type ${gqlNames.sendItemMagicAuthLinkResult} {
        code: AuthErrorCode
        message: String
      }

      enum AuthErrorCode {
        PASSWORD_AUTH_FAILURE
        PASSWORD_AUTH_IDENTITY_NOT_FOUND
        PASSWORD_AUTH_SECRET_NOT_SET
        PASSWORD_AUTH_MULTIPLE_IDENTITY_MATCHES
        PASSWORD_AUTH_SECRET_MISMATCH
        AUTH_TOKEN_REQUEST_IDENTITY_NOT_FOUND
        AUTH_TOKEN_REQUEST_MULTIPLE_IDENTITY_MATCHES
        AUTH_TOKEN_REDEMPTION_INVALID_TOKEN
        AUTH_TOKEN_REDEMPTION_TOKEN_EXPIRED
        AUTH_TOKEN_REDEMPTION_TOKEN_REDEEMED
        AUTH_TOKEN_INTERNAL_ERROR
        CUSTOM_ERROR
      }
    `,

    resolvers: {
      Mutation: {
        async [gqlNames.authenticateItemWithPassword](root: any, args: any, ctx: any) {
          const list = ctx.keystone.lists[listKey];
          const result = await attemptAuthentication(args, list);

          if (!result.success) {
            const message = getErrorMessage(identityField, secretField, list.adminUILabels.singular, list.adminUILabels.plural, result.code);
            return { __typename: gqlNames.ItemAuthenticationWithPasswordFailure, code: AuthErrorCode[result.code], message };
          }

          const token = await ctx.startSession({ listKey: 'User', itemId: result.item.id });
          return { __typename: gqlNames.ItemAuthenticationWithPasswordSuccess, token, item: result.item };
        },
        async [gqlNames.sendItemPasswordResetLink](root: any, args: any, ctx: any) {
          const list = ctx.keystone.lists[listKey];
          const identity = args[identityField];
          const result = await updateAuthToken('passwordReset', identity, list, ctx);

          if (result.success) {
            await passwordResetLink?.sendToken({ itemId: result.itemId, identity, token: result.token });
          }
          if (!result.success && result.code) {
            const message = getErrorMessage(identityField, secretField, list.adminUILabels.singular, list.adminUILabels.plural, result.code);
            return { code: AuthErrorCode[result.code], message };
          }
          return {};
        },
        async [gqlNames.sendItemMagicAuthLink](root: any, args: any, ctx: any) {
          const list = ctx.keystone.lists[listKey];
          const identity = args[identityField];

          const result = await updateAuthToken('magicAuth', identity, list, ctx);
          if (result.success) {
            await sendMagicAuthLink({ itemId: result.itemId, identity, token: result.token });
          }
          if (!result.success && result.code) {
            const message = getErrorMessage(identityField, secretField, list.adminUILabels.singular, list.adminUILabels.plural, result.code);
            return { code: AuthErrorCode[result.code], message };
          }
          return {};
        },
      },
      Query: {
        async authenticatedItem(root: any, args: any, ctx: any) {
          if (typeof ctx.session?.itemId === 'string' && typeof ctx.session.listKey === 'string') {
            const item = (
              await ctx.keystone.lists[ctx.session.listKey].adapter.find({
                id: ctx.session.itemId,
              })
            )[0];
            if (!item) return null;
            return {
              ...item,
              // TODO: is this okay?
              // probably yes but ¯\_(ツ)_/¯
              __typename: ctx.session.listKey,
            };
          }
          return null;
        },
      },
      AuthenticatedItem: {
        __resolveType(rootVal: any) {
          return rootVal.__typename;
        },
      },
    },
  });
}
