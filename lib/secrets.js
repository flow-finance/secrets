const {spawnSync} = require( 'child_process');
const { SecretsManagerClient, GetSecretValueCommand, CreateSecretCommand } = require('@aws-sdk/client-secrets-manager');

const DEFAULT_REGION = 'us-west-2';
const MAX_RETRY_ATTEMPTS = 3;

/**
 * Class for loading all secrets from AWS Secrets Manager.
 */
class Secrets {

	/**	
	 * @constructor
	 * @param  {Object} options class options
	 * @param  {String} options.region The AWS region where your secrets saved (default: AWS_PROFILE environment variable or 'us-west-2' if unset).
	 * @param  {String} options.delimiter delimiter used in key names (default:'/')
	 * @param  {String} options.env The environment or stage the secret belongs to
	 * e.g.: staging/database/secret. This is important when generating secret 
	 * config so that only that only secrets for specific environments are used.
	 * If not provided `process.env.NODE_ENV` is used.
	 * @param  {String|Array} options.namespace An optional namespace to be prepended.
	 * e.g.: my-namespace/production/database/secret
	 * @param  {Boolean} options.all Ignore the environment and retrieve all secrets
	 */	 
	constructor(options={}) {
		
		this.delimiter = options.delimiter || '/';
		
		this.env = options.env || process.env.NODE_ENV;

		this.region = options.region || process.env.AWS_REGION || DEFAULT_REGION;
		
		if (options.all) {
			this.env = null;
		}
		
		if (options.namespace && options.namespace.length) {
			
			if (Array.isArray(options.namespace)) {
				this.namespace = options.namespace.join(this.delimiter);
			}
			
			this.namespace = options.namespace;

		}
		
		this.retryAttempts = 0;

		this.secretsmanager = new SecretsManagerClient({region: this.region});

	}

	static get MAX_RETRY_ATTEMPTS () { return MAX_RETRY_ATTEMPTS; }

	/**	
	 * getSecret - retrieve a secret from AWS Secrets Manager
	 * 	 
	 * @param  {Object} options={}
	 * @param  {String} options.id The id of the secret to retireve
	 * @param  {String} options.version The secret version 
	 * @param  {String} options.stage staging label attached to the version
	 * @param  {String} options.raw return all the raw data from AWS instead of 
	 * 	just the secret
	 * @return {Promise} A Promise contaning secret details
	 */	 
	async getSecret (options={}) {
		
		let secret,
			params = {
				SecretId: options.id, 
			};
		
		if (options.version) {
			params.VersionId = options.version;
		} else if (options.stage) {
			params.VersionStage = options.stage;
		}

    const command = new GetSecretValueCommand(params);
		
		try {
			secret = await this.secretsmanager.send(command);
		} catch (err) {

			if (
				err.errorMessage &&
				err.errorMessage === 'Rate exceeded' &&
				this.retryAttempts <= this.MAX_RETRY_ATTEMPTS
			) {
				
				this.retryAttempts++;
				console.error(new Error( `Rate limit exceeded. Retry attempt ${this.retryAttempts} of ${this.MAX_RETRY_ATTEMPTS}.`) );
				return new Promise( (resolve, reject) => {
					setTimeout( () => {
						this.getSecret(options)
							.then(resolve)
							.catch(reject);
					}, 1050);
				});

			}

			return Promise.reject(err);
		}
		
		if (options.raw) {
			return Promise.resolve(secret);
		}
		
		return Promise.resolve(secret.SecretString);
	}

	/**	
	 * getSecretSync - Synchronously retrieve a secret from AWS Secrets Manager
	 * 	 
	 * @param  {Object} options={}
	 * @param  {String} options.id The id of the secret to retireve
	 * @param  {String} options.version The secret version 
	 * @param  {String} options.stage staging label attached to the version
	 * @param  {String} options.raw return all the raw data from AWS instead of 
	 * 	just the secret
	 * @return {Object} A Promise contaning secret details
	 */	 
	getSecretSync (options={}) {

		const args = {
			method: 'getSecret',
			options: {
				region: this.region,
			},
			arguments: options
		};
		
		const result = spawnSync( 'node', [ __dirname + '/readline' ], {
			input: JSON.stringify(args),
			maxBuffer: 15 // max size is 10 Kb
		});

		let res = JSON.parse( result.stdout.toString() );
		
		if( res.error ) {
			throw new Error( res.error.message || res.error.code );
		}

		// If the result is a JSON string try to parse it
		if ( Object.prototype.toString.call(res.config) === '[object String]' ) {
			try {
				res.config = JSON.parse(res.config);
			} catch (err) {}
		}
		
		return res.config || {};

	}
	
	/**	
	 * createSecret - create a new secret in AWS Secrets Manager. This method
	 * will automatically append the namespace and env it they are provided
	 * 	 
	 * @param  {Object} options={} secret options
	 * @param  {String} name secret name
	 * @param  {String} description secret description
	 * @param  {String} token secret token
	 * @param  {String} kms secret kms
	 * @param  {[Object]} tags secret tags
	 * @param  {Object:String} secrets secret string
	 * @param  {Buffer} secretsBinary secret secrets as binary
	 * @return {Promise} A Promise containing the ARN Name and VersionID
	 */	 
	createSecret (options={}) {
		
		if (Array.isArray(options.name)) {
			options.name = options.name.join(this.delimiter);
		}
		
		if (this.env) {
			options.name = `${this.env}${this.delimiter}${options.name}`;
		}

		if (this.namespace) {
			options.name = `${this.namespace}${this.delimiter}${options.name}`;
		}

		let params = {
			Name: options.name
		};

		if (options.description && options.description.length) {
			params.Description = options.description;
		}

		if (options.token && options.token.length) {
			params.ClientRequestToken = options.token;
		}

		if (options.kms && options.kms.length) {
			params.KmsKeyId = options.kms;
		}
		
		if (Array.isArray(options.tags)) {
			params.Tags = options.tags;
		}
		
		if (options.secretsBinary) {

			params.SecretBinary = options.secretsBinary;
			
		} else {
			
			if ( Object.prototype.toString.call(options.secrets) === '[object String]' ) {
				params.SecretString = options.secrets;
			} else {
				params.SecretString = JSON.stringify(options.secrets);
			}

		}

    const command = new CreateSecretCommand(params);
		return this.secretsmanager.send(command);
	}

	/**	
	 * _parseSecrets - convert secret names into proper config object using 
	 * 
	 * @param  {Array} list the list of secrets retuned from Secrets Mananger
	 * @return {Object}
	 */	 
	_parseSecrets(list) {
		
		let res = {};
		let config = {};


		for (let secret of list) {
		
			let name = secret.Name
				.replace(this.namespace+this.delimiter, '')
				.replace(this.env+this.delimiter, '');
			
			
			try {
				config[name] = JSON.parse(secret.SecretString);
			} catch (err) {
				config[name] = secret.SecretString;
			}
		
		}
		
		for (let item in config) {
		
			let cache = res,
				parts = item.split(this.delimiter),
				key = parts.pop(),
				part;
		
			while (parts.length) {
				part = parts.shift();
				cache = cache[part] = cache[part] || {};
			}
			cache[key] = config[item];
		}

		return res;
		
	}
}

module.exports = Secrets;
