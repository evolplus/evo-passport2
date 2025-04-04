import mysql2, { RowDataPacket } from 'mysql2/promise';
import { AuthenticationConfig, BasePassport, ExternalIdentification, MS_A_DAY } from './model';

/**
 * MySQL Passport implementation
 */
export class MySqlPassport extends BasePassport {
    private connection: mysql2.Connection;

    constructor(connection: mysql2.Connection, authConfig: AuthenticationConfig) {
        super(authConfig);
        this.connection = connection;
    }

    override async queryRefreshToken(userId: string): Promise<string | undefined> {
        const [rows] = await this.connection.execute<RowDataPacket[]>('SELECT refresh_token FROM tokens WHERE user_id = ? AND refresh_token_expires_at > ?', [userId, Date.now()]);
        if (rows.length > 0) {
            return rows[0].refresh_token;
        }
    }

    override async queryAccessToken(accessToken: string): Promise<string | undefined> {
        const [rows] = await this.connection.execute<RowDataPacket[]>('SELECT user_id FROM tokens WHERE access_token = ? AND access_token_expires_at > ?', [accessToken, Date.now()]);
        if (rows.length > 0) {
            return rows[0].user_id;
        }
    }

    override async saveRefreshToken(userId: string, refreshToken: string): Promise<void> {
        let expireTs = Date.now() + this.authConfig.refreshTokenExpiry * MS_A_DAY;
        await this.connection.execute('INSERT INTO tokens (user_id, refresh_token, refresh_token_expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE refresh_token = ?, refresh_token_expires_at = ?', [userId, refreshToken, expireTs, refreshToken, expireTs]);
    }

    override async saveAccessTokenToken(userId: string, accessToken: string): Promise<void> {
        let expireTs = Date.now() + this.authConfig.accessTokenExpiry * MS_A_DAY;
        await this.connection.execute('INSERT INTO tokens (user_id, access_token, access_token_expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE access_token = ?, access_token_expires_at = ?', [userId, accessToken, expireTs, accessToken, expireTs]);
    }

    override async mapUserId(authProvider: string, externalUserId: string): Promise<string> {
        const [rows] = await this.connection.execute<RowDataPacket[]>('SELECT user_id FROM user_mapping WHERE auth_provider = ? AND external_user_id = ?', [authProvider, externalUserId]);
        if (rows.length > 0) {
            return rows[0].user_id;
        } else {
            const newUserId = this.generateUserId();
            await this.connection.execute('INSERT INTO user_mapping (auth_provider, external_user_id, user_id) VALUES (?, ?, ?)', [authProvider, externalUserId, newUserId]);
            return newUserId;
        }
    }

    override async mapUserIdReversed(userId: string): Promise<ExternalIdentification | undefined> {
        const [rows] = await this.connection.execute<RowDataPacket[]>('SELECT auth_provider, external_user_id FROM user_mapping WHERE user_id = ?', [userId]);
        if (rows.length > 0) {
            return {
                authProvider: rows[0].auth_provider,
                userId: rows[0].external_user_id
            };
        }
    }

    override async deleteUser(userId: string): Promise<void> {
        await this.connection.execute('DELETE FROM user_mapping WHERE user_id = ?', [userId]);
        await this.connection.execute('DELETE FROM tokens WHERE user_id = ?', [userId]);
    }

    override async logoutUser(userid: string): Promise<void> {
        await this.connection.execute('DELETE FROM tokens WHERE user_id = ?', [userid]);
        await this.connection.execute('DELETE FROM user_mapping WHERE user_id = ?', [userid]);
    }

    override async setUserName(userId: string, name: string): Promise<void> {
        await this.connection.execute('INSERT INTO users (user_id, name) VALUES (?, ?) ON DUPLICATE KEY UPDATE name = ?', [userId, name, name]);
    }

    override async getUserName(userId: string): Promise<string | undefined> {
        const [rows] = await this.connection.execute<RowDataPacket[]>('SELECT name FROM users WHERE user_id = ?', [userId]);
        if (rows.length > 0) {
            return rows[0].name;
        }
    }

    override async close(): Promise<void> {
        await this.connection.end();
        this.connection = undefined!;
    }
}