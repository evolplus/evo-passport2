import { describe, expect, test } from '@jest/globals';
import { RedisPassport } from '../lib/redis-passport';
import { MySqlPassport } from '../lib/mysql-passport';
import { AuthenticationConfig, PassportIf, TokenData } from '../lib/model';
import { generateKeyPairSync, randomBytes } from 'crypto';
import mysql2 from 'mysql2/promise';

let authConfigs: AuthenticationConfig[] = [],
    { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
        },
    });
authConfigs.push({
    configName: 'jwt & no refresh',
    accessTokenExpiry: 30,
    refreshTokenExpiry: 365,
    accessTokenType: 'jwt',
    userIdSize: 8,
    jwtIssuer: 'test',
    jwtSecret: privateKey,
    refreshPolicy: 'none',
});
authConfigs.push({
    configName: 'jwt & refresh',
    accessTokenExpiry: 30,
    refreshTokenExpiry: 365,
    accessTokenType: 'jwt',
    userIdSize: 8,
    jwtIssuer: 'test',
    jwtSecret: privateKey,
    refreshPolicy: 'refresh',
});
authConfigs.push({
    configName: 'raw & no refresh',
    accessTokenExpiry: 30,
    refreshTokenExpiry: 365,
    accessTokenType: 'raw',
    userIdSize: 8,
    jwtIssuer: 'test',
    jwtSecret: privateKey,
    refreshPolicy: 'none',
});
authConfigs.push({
    configName: 'raw & refresh',
    accessTokenExpiry: 30,
    refreshTokenExpiry: 365,
    accessTokenType: 'raw',
    userIdSize: 8,
    jwtIssuer: 'test',
    jwtSecret: privateKey,
    refreshPolicy: 'refresh',
});

for (let authConfig of authConfigs) {
    describe(`Test on local Redis with ${authConfig.configName}`, () => {
        let passport: PassportIf = new RedisPassport({
            host: 'localhost',
            port: 6379,
        }, authConfig);
        createTests(passport, authConfig);
    });
    describe(`Test on local MySql with ${authConfig.configName}`, () => {
        let passport: PassportIf = new MySqlPassport(mysql2.createPool("mysql://test:test@localhost/passport_test"), authConfig);
        createTests(passport, authConfig);
    });
}

function createTests(passport: PassportIf, authConfig: AuthenticationConfig) {
    let provider = 'test',
        extUserId = randomBytes(16).toString('hex'),
        userId: string,
        userName = 'Test User',
        token: TokenData;

    //basic tests first
    test('Map userId', async () => {
        userId = await passport.mapUserId(provider, extUserId);
        expect(userId).toBeDefined();
    });
    test('Create token', async () => {
        token = await passport.createAccessToken(userId);
        expect(token).toBeDefined();
        expect(token.accessToken).toBeDefined();
        expect(token.refreshToken).toBeDefined();
    });
    test('Set user name', async () => {
        await passport.setUserName(userId, userName);
    });

    // others
    test('Map userId reversed', async () => {
        let extId = await passport.mapUserIdReversed(userId);
        expect(extId).toBeDefined();
        expect(extId?.authProvider).toEqual(provider);
        expect(extId?.userId).toEqual(extUserId);
    });
    test('Verify token', async () => {
        let session = await passport.verifyToken(token.accessToken!);
        expect(session).toBeDefined();
        expect(session?.userId).toEqual(userId);
    });
    test('Refresh token', async () => {
        let newToken = await passport.refreshToken(userId, token.refreshToken!);
        expect(newToken).toBeDefined();
        expect(newToken.accessToken).toBeDefined();
        expect(newToken.refreshToken).toBeDefined();
        expect(newToken.accessToken).not.toEqual(token.accessToken);

        if (authConfig.refreshPolicy === 'none') {
            expect(newToken.refreshToken).toEqual(token.refreshToken);
        } else {
            expect(newToken.refreshToken).not.toEqual(token.refreshToken);
        }
        let session = await passport.verifyToken(newToken.accessToken!);
        expect(session).toBeDefined();
        expect(session?.userId).toEqual(userId);
        expect(session?.accessToken).toEqual(newToken.accessToken);
    });

    test('Get user name', async () => {
        let name = await passport.getUserName(userId);
        expect(name).toBeDefined();
        expect(name).toEqual(userName);
    });
    test('Close passport', async () => {
        await passport.close();
    });
}