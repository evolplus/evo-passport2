import * as jwt from 'jsonwebtoken';
import crypto from 'crypto';

export type TokenData = {
    accessToken?: string;
    refreshToken?: string;
}

// The external identification of a user in an external authentication system
export type ExternalIdentification = {
    authProvider: string;
    userId: string;
}

// Access token types. This framework supports JWT and raw access tokens. JWT is recommended for security and performance reasons.
export type AccessTokenType = 'jwt' | 'raw';

// Refresh policy. If set to 'none', the refresh token will not be updated on each access token refresh. This is useful for long-lived refresh tokens.
export type RefreshPolicy = 'none' | 'refresh';

// Authentication configuration. This is used to configure the authentication system.
export type AuthenticationConfig = {
    configName?: string;
    accessTokenType: AccessTokenType;
    jwtSecret?: string;
    jwtIssuer?: string;
    accessTokenExpiry: number; // in days
    refreshTokenExpiry: number; // in days
    userIdSize: number; // size of the userId in bytes
    refreshPolicy: RefreshPolicy;
}
export const MS_A_DAY = 24 * 60 * 60 * 1000;

// The session object. This is used to store the session information of a user.
export type Session = {
    accessToken?: string;
    userId?: string;
    name?: string;
}

// The interface for the passport system. This is used to define the methods that need to be implemented by the passport system.
export interface PassportIf {
    /**
     * Creates a new access token for the user. If the refresh token is not provided, a new refresh token will be created.
     * @param userId The userId of the user to create the access token for.
     */
    createAccessToken(userId: string, refreshToken?: string): Promise<TokenData>;

    /**
     * Refreshes the access token for the user. If the refresh token is not valid, an error will be thrown.
     * @param userId The userId of the user to create the access token for.
     * @param refreshToken The refresh token to use. 
     */
    refreshToken(userId: string, refreshToken: string): Promise<TokenData>;

    /**
     * Verifies the access token. If the access token is valid, the session object will be returned. If the access token is not valid, undefined will be returned.
     * @param accessToken The access token to verify.
     */
    verifyToken(accessToken: string): Promise<Session | undefined>;

    /**
     * Maps the userId to the external userId in the external authentication system. If the userId is not found, a new userId will be created.
     * @param authProvider The authentication provider. This is used to identify the external authentication system.
     * @param externalUserId The userId of the user in the external authentication system. This is used to identify the user in the external authentication system.
     */
    mapUserId(authProvider: string, externalUserId: string): Promise<string>;

    /**
     * Maps the userId to the external userId in the external authentication system. If the userId is not found, undefined will be returned.
     * @param userId The userId of the user in the internal authentication system. This is used to identify the user in the internal authentication system.
     */
    mapUserIdReversed(userId: string): Promise<ExternalIdentification | undefined>;

    /**
     * Deletes the user from the authentication system. This will not affect the credentical of the user from the external authentication system.
     * @param userId The userId of the user to delete.
     */
    deleteUser(userId: string): Promise<void>;

    /**
     * Logs out the user from the authentication system. This will not affect the credentical of the user from the external authentication system.
     * @param userid The userId of the user to logout.
     */
    logoutUser(userid: string): Promise<void>;

    /**
     * Sets the name of the user. This is used to store the name of the user in the authentication system.
     * @param userId The userId of the user to set the name for.
     * @param name Name of the user to set.
     */
    setUserName(userId: string, name: string): Promise<void>;

    /**
     * Gets the name of the user. This is used to get the name of the user from the authentication system.
     * @param userId The userId of the user to get the name for.
     */
    getUserName(userId: string): Promise<string | undefined>;

    /**
     * Closes the passport system. This is used to close the passport system and release any resources that are used by the passport system.
     */
    close(): Promise<void>;
}

/**
 * Base class for the passport system. This is used to define the methods that need to be implemented by the passport system.
 */
export abstract class BasePassport implements PassportIf {

    constructor(protected authConfig: AuthenticationConfig) { }

    /**
     * Creates a new JWT for the user. This is used to create a new JWT for the user.
     * @param userId The userId of the user to create the JWT for.
     * @returns The JWT for the user.
     */
    protected createJwt(userId: string): string {
        if (!this.authConfig.jwtSecret) {
            throw new Error("JWT secret is not defined");
        }
        const payload = {
            jti: this.createRandomBytes(),
            iss: this.authConfig.jwtIssuer,
            name: this.getUserName(userId),
            sub: userId,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * this.authConfig.accessTokenExpiry), // 30 days
        };
        return jwt.sign(payload, this.authConfig.jwtSecret, {
            algorithm: 'RS256',
        });
    }

    /**
     * This is used to create a random string for the tokens.
     * @returns A random string of 32 bytes in hex format.
     */
    protected createRandomBytes(): string {
        return crypto.randomBytes(16).toString('hex');
    }

    /**
     * Generates a random userId for the user. This is used to create a new userId for the user.
     * @returns A random userId of 8 bytes in decimal format.
     */
    protected generateUserId(): string {
        return crypto.randomBytes(this.authConfig.userIdSize).readBigUInt64BE(0).toString(10);
    }

    abstract queryRefreshToken(refreshToken: string): Promise<string | undefined>;
    abstract queryAccessToken(userId: string): Promise<string | undefined>;
    abstract saveRefreshToken(userId: string, refreshToken: string): Promise<void>;
    abstract saveAccessTokenToken(userId: string, accessToken: string): Promise<void>;
    abstract mapUserId(authProvider: string, externalUserId: string): Promise<string>;
    abstract mapUserIdReversed(userId: string): Promise<ExternalIdentification | undefined>;
    abstract deleteUser(userId: string): Promise<void>;
    abstract logoutUser(userid: string): Promise<void>;
    abstract setUserName(userId: string, name: string): Promise<void>;
    abstract getUserName(userId: string): Promise<string | undefined>;
    abstract close(): Promise<void>;

    /**
     * Creates a new access token for the user. If the refresh token is not provided, a new refresh token will be created.
     * @param userId The userId of the user to create the access token for.
     * @param refreshToken The refresh token to use. If not provided, a new refresh token will be created.
     * @returns A promise that resolves to the access token and refresh token.
     */
    async createAccessToken(userId: string, refreshToken?: string): Promise<TokenData> {
        if (!refreshToken) {
            refreshToken = this.createRandomBytes();
            await this.saveRefreshToken(userId, refreshToken);
        }
        if (this.authConfig.accessTokenType === 'jwt') {
            return {
                accessToken: this.createJwt(userId),
                refreshToken
            };
        } else {
            let accessToken = this.createRandomBytes();
            await this.saveAccessTokenToken(userId, accessToken);
            return {
                accessToken,
                refreshToken
            };
        }
    }

    /**
     * Refreshes the access token for the user. If the refresh token is not valid, an error will be thrown.
     * @param userId The userId of the user to create the access token for.
     * @param refreshToken The refresh token to use. If not provided, a new refresh token will be created.
     * @returns A promise that resolves to the access token and refresh token.
     */
    async refreshToken(userId: string, refreshToken: string): Promise<TokenData> {
        let check = await this.queryRefreshToken(userId);
        if (check !== refreshToken) {
            throw new Error('Invalid refresh token');
        }
        if (this.authConfig.refreshPolicy === 'none') {
            return await this.createAccessToken(userId, refreshToken);
        }
        return await this.createAccessToken(userId);
    }

    /**
     * Verifies the access token. If the access token is valid, the session object will be returned. If the access token is not valid, undefined will be returned.
     * @param accessToken The access token to verify.
     * @returns A promise that resolves to the session object if the access token is valid, or undefined if the access token is not valid.
     */
    async verifyToken(accessToken: string): Promise<Session | undefined> {
        if (this.authConfig.accessTokenType == 'jwt') {
            try {
                let payload = jwt.verify(accessToken, this.authConfig.jwtSecret!) as jwt.JwtPayload;
                return {
                    userId: payload.sub,
                    accessToken: accessToken,
                    name: payload.name
                };
            } catch(e) {
                return;
            }
        } else {
            let userId = await this.queryAccessToken(accessToken);
            if (userId) {
                return {
                    userId: userId,
                    accessToken: accessToken,
                    name: await this.getUserName(userId)
                };
            }
        }
    }
}
