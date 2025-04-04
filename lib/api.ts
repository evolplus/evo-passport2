import { PassportIf, Session } from "./model";
import { Application, NextFunction, Request, Response } from "express";

declare global {
    namespace Express {
        export interface Request {
            session?: Session;
        }
    }
}

/**
 * 
 * @param app Install express middleware handler that will check the authentication header for a bearer token.
 * @param passport The passport instance to use for authentication.
 */
export function installExpressMiddleware(app: Application, passport: PassportIf) {
    app.use(async (req: Request, resp: Response, next: NextFunction) => {
        let auth = req.headers['authentication'] as string | undefined;
        if (auth && auth.startsWith("Bearer ")) {
            auth = auth.substring(7);
            let session;
            if (session = await passport.verifyToken(auth)) {
                req.session = session;
                return next();
            }
        }
        resp.status(401).json({
            error: "Unauthorized"
        });
    });
}