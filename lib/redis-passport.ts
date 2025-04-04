import { Cluster, Redis } from "ioredis";
import { AuthenticationConfig, BasePassport, ExternalIdentification, MS_A_DAY, PassportIf } from "./model";

interface RedisConfig {
    host: string;
    port: number;
    password?: string;
    db?: number;
    prefix?: string;
}

interface RedisClusterConfig {
    nodes: { host: string, port: number }[];
    password?: string;
    db?: number;
    prefix?: string;
}

/**
 * Redis Passport implementation
 */
export class RedisPassport extends BasePassport {
    private redisClient: Redis | Cluster;
    private prefix: string;

    constructor(redisConfig: RedisConfig | RedisClusterConfig, authConfig: AuthenticationConfig) {
        super(authConfig);
        if ('nodes' in redisConfig) {
            this.redisClient = new Redis.Cluster(redisConfig.nodes, {
                redisOptions: {
                    password: redisConfig.password,
                    db: redisConfig.db
                }
            });
        } else {
            this.redisClient = new Redis(redisConfig);
        }
        this.prefix = redisConfig.prefix || "passport:";
    }

    private refreshTokenKey(userId: string): string {
        return `${this.prefix}.r.${userId}`;
    }

    private accessTokenKey(accessToken: string): string {
        return `${this.prefix}.a.${accessToken}`;
    }

    private userIdKey(authProvider: string, externalUserId: string): string {
        return `${this.prefix}.u.${authProvider}.${externalUserId}`;
    }

    private reversedKey(userId: string): string {
        return `${this.prefix}.i.${userId}`;
    }

    private userNameKey(userId: string): string {
        return `${this.prefix}.n.${userId}`;
    }

    override async queryRefreshToken(userId: string): Promise<string | undefined> {
        let token = await this.redisClient.get(this.refreshTokenKey(userId));
        if (token) {
            return token;
        }
    }

    override async queryAccessToken(accessToken: string): Promise<string | undefined> {
        let userId = await this.redisClient.get(this.accessTokenKey(accessToken));
        if (userId) {
            return userId;
        }
    }

    override async saveRefreshToken(userId: string, refreshToken: string): Promise<void> {
        await this.redisClient.set(this.refreshTokenKey(userId), refreshToken, 'PX', this.authConfig.refreshTokenExpiry * MS_A_DAY);
    }

    override async saveAccessTokenToken(userId: string, accessToken: string): Promise<void> {
        await this.redisClient.set(this.accessTokenKey(accessToken), userId, 'PX', this.authConfig.accessTokenExpiry * MS_A_DAY);
    }

    override async mapUserId(authProvider: string, externalUserId: string): Promise<string> {
        let key = this.userIdKey(authProvider, externalUserId),
            userId = await this.redisClient.get(key);
        if (userId) {
            return userId;
        }
        userId = this.generateUserId();
        let ck = await this.redisClient.setnx(key, userId);
        if (ck === 1) {
            await this.redisClient.set(this.reversedKey(userId), JSON.stringify({ authProvider, userId: externalUserId }));
            return userId;
        }
        throw new Error("User ID creation failed");
    }

    override async mapUserIdReversed(userId: string): Promise<ExternalIdentification | undefined> {
        let data = await this.redisClient.get(this.reversedKey(userId));
        if (data) {
            return JSON.parse(data);
        }
    }

    override async deleteUser(userId: string): Promise<void> {
        let reversedKey = this.reversedKey(userId),
            data = await this.redisClient.get(reversedKey);
        if (data) {
            let { authProvider, externalUserId } = JSON.parse(data);
            await this.redisClient.del(this.userIdKey(authProvider, externalUserId));
            await this.redisClient.del(reversedKey);
        }
        await this.redisClient.del(this.refreshTokenKey(userId));
        await this.redisClient.del(this.accessTokenKey(userId));
    }

    override async logoutUser(userId: string): Promise<void> {
        await this.redisClient.del(this.refreshTokenKey(userId));
        await this.redisClient.del(this.accessTokenKey(userId));
    }

    override async setUserName(userId: string, name: string): Promise<void> {
        await this.redisClient.set(this.userNameKey(userId), name);
    }

    override async getUserName(userId: string): Promise<string | undefined> {
        let name = await this.redisClient.get(this.userNameKey(userId));
        if (name) {
            return name;
        }
    }

    override async close(): Promise<void> {
        await this.redisClient.quit();
        if ('nodes' in this.redisClient) {
            await (this.redisClient as Cluster).disconnect();
        }
        this.redisClient = undefined!;
    }

}