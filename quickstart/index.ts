import { createHash } from "crypto";
import * as aws from "@pulumi/aws";
import * as apigateway from "@pulumi/aws-apigateway";
import {
	CognitoIdentityClient,
	CognitoIdentityClientConfig,
	GetOpenIdTokenForDeveloperIdentityCommand,
	GetOpenIdTokenForDeveloperIdentityCommandInput,
} from "@aws-sdk/client-cognito-identity";
import {
	DynamoDBClient,
	DynamoDBClientConfig,
	PutItemCommand,
	PutItemCommandInput,
	GetItemCommand,
	GetItemCommandInput,
	DeleteItemCommand,
	DeleteItemCommandInput,
} from "@aws-sdk/client-dynamodb";
import { createRemoteJWKSet, jwtVerify, decodeJwt } from 'jose'

const getBody = (ev: any) =>
	!ev.body
		? ev.body
		: ev.isBase64Encoded
			? JSON.parse(Buffer.from(ev.body, 'base64').toString('utf8'))
			: JSON.parse(ev.body)

// Identity Pool
const cognitoIdentityClientConfig: CognitoIdentityClientConfig = {
	region: "us-east-1"
}

const developerProviderName = "developer-provider"

const identityPool = new aws.cognito.IdentityPool("identity-pool", {
	identityPoolName: "identity-pool",
	developerProviderName,
	allowUnauthenticatedIdentities: false,
});

const authenticatedRole = new aws.iam.Role("authenticatedRole", {
	assumeRolePolicy: {
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Principal: {
					Federated: "cognito-identity.amazonaws.com"
				},
				Action: "sts:AssumeRoleWithWebIdentity",
				Condition: {
					StringEquals: {
						"cognito-identity.amazonaws.com:aud": identityPool.id
					},
					"ForAnyValue:StringLike": {
						"cognito-identity.amazonaws.com:amr": "authenticated"
					}
				}
			}
		]
	}
});

const unauthenticatedRole = new aws.iam.Role("unauthenticatedRole", {
	assumeRolePolicy: {
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Principal: {
					Federated: "cognito-identity.amazonaws.com"
				},
				Action: "sts:AssumeRoleWithWebIdentity",
				Condition: {
					StringEquals: {
						"cognito-identity.amazonaws.com:aud": identityPool.id
					},
					"ForAnyValue:StringLike": {
						"cognito-identity.amazonaws.com:amr": "unauthenticated"
					}
				}
			}
		]
	}
});

const authenticatedRolePolicy = new aws.iam.RolePolicy("authenticatedRolePolicy", {
	role: authenticatedRole.id,
	policy: {
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Action: [
					"mobileanalytics:PutEvents",
					"cognito-sync:*",
					"cognito-identity:*"
				],
				Resource: [
					"*"
				]
			}
		]
	},
});

const unauthenticatedRolePolicy = new aws.iam.RolePolicy("unauthenticatedRolePolicy", {
	role: unauthenticatedRole.id,
	policy: {
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Action: [
					"mobileanalytics:PutEvents",
					"cognito-sync:*",
				],
				Resource: [
					"*"
				]
			}
		]
	},
});

const identityPoolRoleAttachment = new aws.cognito.IdentityPoolRoleAttachment("identityPoolRoleAttachment", {
	identityPoolId: identityPool.id,
	roles: {
		authenticated: authenticatedRole.arn,
		unauthenticated: unauthenticatedRole.arn,
	},
});

// DynamoDB
const dynamoDBClientConfig: DynamoDBClientConfig = {
	region: "us-east-1"
}

const dynamodbSessionsTable = new aws.dynamodb.Table("dynamodbSessionsTable", {
	attributes: [
		{
			name: "UserId",
			type: "S",
		},
	],
	hashKey: "UserId",
	billingMode: "PAY_PER_REQUEST",
	streamEnabled: true,
	streamViewType: "NEW_IMAGE",
})

const dynamodbSavedSessionsTable = new aws.dynamodb.Table("dynamodbSavedSessionsTable", {
	attributes: [
		{
			name: "UserId",
			type: "S",
		},
		{
			name: "Timestamp",
			type: "N",
		},
	],
	hashKey: "UserId",
	rangeKey: "Timestamp",
	billingMode: "PAY_PER_REQUEST",
})

const saveSession = new aws.lambda.CallbackFunction("saveSession", {
	callback: async (ev: any, ctx, cb) => {
		await Promise.all(ev.Records.map(async (record: any) => {
			if (record.eventName == 'INSERT' || record.eventName == 'MODIFY') {
				const dynamoInput: PutItemCommandInput = {
					TableName: dynamodbSavedSessionsTable.name.get(),
					Item: {
						...record.dynamodb.NewImage,
						Timestamp: { N: `${Math.floor(Date.now() / 1000)}` },
					},
				}
				const dynamoDBClient = new DynamoDBClient(dynamoDBClientConfig);
				const dynamoCommand = new PutItemCommand(dynamoInput);
				await dynamoDBClient.send(dynamoCommand);
			}
		}))
		cb(null, `Successfully processed ${ev.Records.length} records.`);
	}
});

const eventSourceMapping = new aws.lambda.EventSourceMapping("example", {
	eventSourceArn: dynamodbSessionsTable.streamArn,
	functionName: saveSession.arn,
	startingPosition: "LATEST",
});

// Functions
const helloWorld = new aws.lambda.CallbackFunction("helloWorld", {
	callback: async (ev, ctx) => ({
		statusCode: 200,
		body: "Hello World!",
	})
});

const login = new aws.lambda.CallbackFunction("login", {
	callback: async (ev: any, ctx) => {
		const body = getBody(ev)
		// TODO: distinguish non silent/silent login
		const { DeviceId } = ev.headers || {}
		const { username, password } = body || {}

		if (!DeviceId || !username || !password) return { statusCode: 400, body: "Missing DeviceId, username or password" }

		// TODO: verify credentials

		const usernameHash = createHash('md5').update(username).digest("hex")

		const input: GetOpenIdTokenForDeveloperIdentityCommandInput = {
			IdentityPoolId: identityPool.id.get(),
			Logins: {
				[developerProviderName]: usernameHash
			},
			TokenDuration: 60 * 60
		}
		const client = new CognitoIdentityClient(cognitoIdentityClientConfig);
		const command = new GetOpenIdTokenForDeveloperIdentityCommand(input);
		const { Token } = await client.send(command);

		if (!Token) return { statusCode: 500, body: "Error creating Token" }

		const dynamoInput: PutItemCommandInput = {
			TableName: dynamodbSessionsTable.name.get(),
			Item: {
				UserId: { S: usernameHash },
				DeviceId: { S: DeviceId },
			},
		}
		const dynamoDBClient = new DynamoDBClient(dynamoDBClientConfig);
		const dynamoCommand = new PutItemCommand(dynamoInput);
		await dynamoDBClient.send(dynamoCommand);

		return {
			statusCode: 200,
			body: JSON.stringify({
				Token,
			})
		};
	},
});

const authorize = new aws.lambda.CallbackFunction("authorize", {
	callback: async (ev: any, ctx) => {
		const { Token, DeviceId } = ev.headers || {}

		let effect = "Deny"

		if (!Token || !DeviceId) {
			return {
				principalId: "my-user",
				policyDocument: {
					Version: "2012-10-17",
					Statement: [
						{
							Action: "execute-api:Invoke",
							Effect: effect,
							Resource: ev.methodArn,
						},
					],
				}
			}
		}

		try {
			const JWKS = createRemoteJWKSet(new URL("https://cognito-identity.amazonaws.com/.well-known/jwks_uri"))
			const jwtOptions = {
				issuer: "https://cognito-identity.amazonaws.com", // set this to the expected "iss" claim on your JWTs
				audience: identityPool.id.get(), // set this to the expected "aud" claim on your JWTs
			}
			const { payload: verifiedToken } = await jwtVerify(Token, JWKS, jwtOptions)
			const userId = (verifiedToken.amr as any)[2].split(':')[3]

			const dynamoInput: GetItemCommandInput = {
				TableName: dynamodbSessionsTable.name.get(),
				Key: {
					UserId: { S: userId },
				}
			}
			const dynamoDBClient = new DynamoDBClient(dynamoDBClientConfig);
			const dynamoCommand = new GetItemCommand(dynamoInput);
			const { Item } = await dynamoDBClient.send(dynamoCommand);

			if (Item && Item.DeviceId.S === DeviceId) {
				effect = "Allow"
			}
		} catch (err) {
			effect = "Deny"
		}

		return {
			principalId: "my-user",
			policyDocument: {
				Version: "2012-10-17",
				Statement: [
					{
						Action: "execute-api:Invoke",
						Effect: effect,
						Resource: ev.methodArn,
					},
				],
			}
		}
	}
});

const logout = new aws.lambda.CallbackFunction("logout", {
	callback: async (ev: any, ctx) => {
		const { Token, DeviceId } = ev.headers || {}

		if (!Token || !DeviceId) return { statusCode: 400, body: "Missing Token or DeviceId" }

		const payload = decodeJwt(Token)
		const userId = (payload.amr as any)[2].split(':')[3]

		const input: DeleteItemCommandInput = {
			TableName: dynamodbSessionsTable.name.get(),
			Key: {
				UserId: {
					S: userId
				},
			}
		}
		const client = new DynamoDBClient(dynamoDBClientConfig);
		const command = new DeleteItemCommand(input);
		await client.send(command);

		return {
			statusCode: 200,
			body: "Logged out"
		};
	},
});

// Gateway
const api = new apigateway.RestAPI("api", {
	routes: [
		{
			path: "/hello-world",
			method: "GET",
			eventHandler: helloWorld,
		},
		{
			path: "/login",
			method: "POST",
			eventHandler: login,
		},
		{
			path: "/authorized/hello-world",
			method: "GET",
			eventHandler: helloWorld,
			authorizers: [
				{
					authType: "custom",
					parameterName: "Token",
					type: "request",
					identitySource: ["method.request.header.Token"],
					handler: authorize,
				},
			],
		},
		{
			path: "/authorized/logout",
			method: "GET",
			eventHandler: logout,
			authorizers: [
				{
					authType: "custom",
					parameterName: "Token",
					type: "request",
					identitySource: ["method.request.header.Token"],
					handler: authorize,
				},
			],
		}
	],
});

export const url = api.url;
