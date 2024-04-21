
type Algorithm =
    | "HS256" | "HS384" | "HS512"
    | "RS256" | "RS384" | "RS512"
    | "ES256" | "ES384" | "ES512"
    | "PS256" | "PS384" | "PS512"
    | "none";

export declare function generateToken({
    data,
    tokenSecret,
    expiresIn,
    algorithm
}: {
    algorithm?: Algorithm;
    data: object;
    tokenSecret: string;
    expiresIn?: string;
}): { token: string | null; success: boolean; message?: string };

export declare function decodedToken({
    tokenSecret,
    token
}: {
    tokenSecret?: string;
    token?: string;
}): { data: any; success: boolean; message?: string };

export declare enum HashAlgorithm {
    SHA1 = 'sha1',
    SHA256 = 'sha256',
    SHA384 = 'sha384',
    SHA512 = 'sha512',
    MD5 = 'md5',
}

export declare function refreshTokenEncoded({
    hashedPass,
    data,
    expiresIn,
    tokenSecret
}: {
    hashedPass?: any;
    data?: object;
    expiresIn?: string;
    tokenSecret: string;
}): string | null;

export declare function passwordHashing({
    salt,
    password,
    algorithm,
    encoding
}: {
    salt?: string;
    password: string;
    algorithm?: HashAlgorithm;
    encoding?: 'base64' | 'hex';
}): {
    salt: string | undefined;
    success: boolean;
    hash: string | undefined;
    message?: string;
};

export declare function checkPassword({
    salt,
    hash,
    password
}: {
    salt: string | undefined;
    hash: string | undefined;
    password: string;
}): boolean;
