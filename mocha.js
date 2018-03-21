
'use strict';

//  dependencies
const root = '../../../../../goatee';
const { Config } = require(`${root}/config/config.js`);
const { Errors } = require(`${root}/shared/errors.js`);
const { PolicyType } = require(`${root}/shared/exp_enums.js`);
const { Auth } = require(`${root}/common/auth.js`);
const { Events } = require(`${root}/shared/api_names.js`);
const { Util } = require(`${root}/shared/util.js`);
const scServer = require(`${root}/socket_cluster/server.js`);
const scClient = require('socketcluster-client');
const database = require(`${root}/database/database.js`);

//  libraries
const async = require('async');
const expect = require('chai').expect;
const uuidv4 = require('uuid/v4');
const knex = require('knex')(Config.knex);
const jwt = require('jsonwebtoken');
const type = require('type-detect');
const base64url = require('base64url');

//  constants
const PASSWORD = 'Test123456';
const EMAIL = `test-${uuidv4()}@test.test`;

class DbEntity {
    constructor(tableName, object) {
        this._tableName = tableName;
        this._object = object;
    }

    get tableName() {
        return this._tableName;
    }

    get object() {
        return this._object;
    }
}

class Policy extends DbEntity {
    constructor(orgPolicyUuid, policyUuid, policyTypeId, name, version) {
        super('policy', {
            org_policy_uuid: orgPolicyUuid,
            policy_uuid: policyUuid,
            policy_type_id: policyTypeId,
            name: name,
            version: version
        });
    }
}

class PolicyDelete extends DbEntity {
    constructor(orgPolicyUuid, policyUuid) {
        super('policy', {
            org_policy_uuid: orgPolicyUuid,
            policy_uuid: policyUuid,
        });
    }
}

class Attribute extends DbEntity {
    constructor(orgPolicyUuid, policyUuid, attributeName, value) {
        super('policy_attribute', {
            org_policy_uuid: orgPolicyUuid,
            policy_uuid: policyUuid,
            attribute_name: attributeName,
            value: value
        });
    }
}

class AttributeDelete extends DbEntity {
    constructor(orgPolicyUuid, policyUuid) {
        super('policy_attribute', {
            org_policy_uuid: orgPolicyUuid,
            policy_uuid: policyUuid
        });
    }
}

class Email extends DbEntity {
    constructor(orgPolicyUuid, policyUuid, email) {
        super('policy_email', {
            org_policy_uuid: orgPolicyUuid,
            policy_uuid: policyUuid,
            email_address: email
        });
    }
}

class EmailDelete extends DbEntity {
    constructor(orgPolicyUuid, policyUuid) {
        super('policy_email', {
            org_policy_uuid: orgPolicyUuid,
            policy_uuid: policyUuid
        });
    }
}

class PropBag {
    get socket() {
        return this._socket;
    }

    set socket(socket) {
        this._socket = socket;
    }

    get authToken() {
        return this._authToken;
    }

    set authToken(authToken) {
        this._authToken = authToken;
    }

    get refreshToken() {
        return this._refreshToken;
    }

    set refreshToken(refreshToken) {
        this._refreshToken = refreshToken;
    }
}

//  uuids for testings, they will be created and deleted
const [uuidOrg, uuidUser, deviceUuid] = [uuidv4(), uuidv4(), uuidv4()];

describe('Login', function () {
    before('Before hook', function (done) {
        const DB = Config.general.databaseName;

        const insert = (DbEntity, cb) => {
            const sql = knex
                .insert(DbEntity.object)
                .into(`${DB}.${DbEntity.tableName}`)
                .toString();

            database.query(sql, err => cb(err));
        };

        async.waterfall([
            (next) => {
                //  we tweak the expiry of JWT before starting the server
                Config.general.authTokenExpiryInSecs = 3;

                scServer.start(err => next(err));
            },
            (next) => {
                database.start(err => next(err));
            },
            (next) => {
                Auth.generatePassword(PASSWORD, null, (err, password, salt) => {
                    next(null, password, salt);
                });
            },
            (password, salt, next) => {
                async.series([
                    (cb) => insert(new Policy(uuidOrg, uuidOrg, PolicyType.idOrg, 'Test organization', 1), cb),
                    (cb) => insert(new Policy(uuidOrg, deviceUuid, PolicyType.idDevice, 'Test device', 1), cb),
                    (cb) => insert(new Policy(uuidOrg, uuidUser, PolicyType.idUser, 'Test user', 1), cb),

                    (cb) => insert(new Attribute(uuidOrg, uuidUser, 'pwPbkdf2HmacSha256Dk', password), cb),
                    (cb) => insert(new Attribute(uuidOrg, uuidUser, 'pwPbkdf2HmacSha256Salt', salt), cb),
                    (cb) => insert(new Attribute(uuidOrg, uuidUser, 'deleted', 'false'), cb),

                    (cb) => insert(new Email(uuidOrg, uuidUser, EMAIL), cb)
                ], err => next(err));
            }
        ], err => {
            done(err);
        });
    });

    const props = new PropBag();

    describe('#authLoginWithCredentials()', function () {
        describe('Log in with good credentials', function () {
            login(props);
        });

        describe('After successfully logging in', function () {
            validateTokens(props);
        });

        describe('Log in with bad credentials', function () {
            login(props, `Should get an "${Errors.invalidCredentials.message}" error`, 'badlogindata@bad.bad', 'badpassword', (err, data) => {
                testError(Errors.invalidCredentials, err, data);
            });

            expectToBeClosed(props);
        });

        describe('Using invalid email format to log in', function () {
            login(props, `Should get an "${Errors.validationError.message}" error`, 'badlogindata', 'badpassword', (err, data) => {
                testError(Errors.validationError, err, data);
            });

            expectToBeClosed(props);
        });

        describe('Log in with good email, bad password', function () {
            login(props, `Should get an "${Errors.invalidCredentials.message}" error`, EMAIL, 'badpassword', (err, data) => {
                testError(Errors.invalidCredentials, err, data);
            });

            expectToBeClosed(props);
        });

        describe('Log in with bad email, good password', function () {
            login(props, `Should get an "${Errors.invalidCredentials.message}" error`, 'test@test.test', PASSWORD, (err, data) => {
                testError(Errors.invalidCredentials, err, data);
            });

            expectToBeClosed(props);
        });

        describe('Login with empty email and password', function () {
            login(props, `Should get an "${Errors.validationError.message}" error`, '', '', (err, data) => {
                testError(Errors.validationError, err, data);
            });

            expectToBeClosed(props);
        });
    });

    describe('#authRefreshTokenExchange()', function () {
        describe('Getting new refresh-token', function () {
            login(props);

            it('Should get a new JWT using the supplied refresh-token after actual JWT expires', function (done) {
                this.timeout(12000);
                this.slow(10000);

                const nowInSecs = Util.getDateNowInSeconds();
                const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                setTimeout(() => {
                    refreshAuthToken(props.socket, lastJwtPayload, props.refreshToken, (err, newRefreshToken) => {
                        if (err) {
                            return done(err);
                        }

                        props.refreshToken = newRefreshToken;

                        return done(null);
                    });
                }, ((props.authToken.exp - nowInSecs) + 1) * 1000);
            });

            it('New auth-token should have a different expiration time', function () {
                expect(props.authToken.exp).not.equal(props.socket.authToken.exp);
                props.authToken = props.socket.authToken;
            });

            validateTokens(props);
        });

        describe('Sending null string instead of refresh-token', function () {
            it(`Should get an "${Errors.validationError.message}" error`, function (done) {
                emitEvent(props.socket, Events.authRefreshTokenExchange, null, (err, newRefreshToken) => {
                    testError(Errors.validationError, err, newRefreshToken);
                    return done(null);
                });
            });

            expectToBeClosed(props);
        });

        describe('Sending a payload with missing keys in the refresh-token', function () {
            login(props);

            it(`Should get an "${Errors.validationError.message}" error`, function (done) {
                const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                const invalidToken = {
                    exp: props.refreshToken.refresh.exp,
                    pl: lastJwtPayload
                };

                emitEvent(props.socket, Events.authRefreshTokenExchange, invalidToken, (err, newRefreshToken) => {
                    testError(Errors.validationError, err, newRefreshToken);
                    return done(null);
                });
            });

            expectToBeClosed(props);
        });

        describe('Sending a payload with additional keys in the refresh-token', function () {
            login(props);

            it(`Should get an "${Errors.validationError.message}" error`, function (done) {
                const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                const invalidToken = {
                    tok: props.refreshToken.refresh.tok,
                    exp: props.refreshToken.refresh.exp,
                    pl: lastJwtPayload,
                    whatever: 'something'
                };

                emitEvent(props.socket, Events.authRefreshTokenExchange, invalidToken, (err, newRefreshToken) => {
                    testError(Errors.validationError, err, newRefreshToken);
                    return done(null);
                });
            });

            expectToBeClosed(props);
        });

        describe('Sending a refresh-token with invalid string for a token', function () {
            login(props);

            it(`Should get an "${Errors.invalidRefreshToken.message}" error`, function (done) {
                const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                const invalidToken = {
                    tok: 'abcdef',
                    exp: props.refreshToken.refresh.exp,
                    pl: lastJwtPayload
                };

                emitEvent(props.socket, Events.authRefreshTokenExchange, invalidToken, (err, newRefreshToken) => {
                    testError(Errors.invalidRefreshToken, err, newRefreshToken);
                    return done(null);
                });
            });

            expectToBeClosed(props);
        });

        describe('Tampering with the salt of the refresh-token', function () {
            login(props);

            it(`Should get an "${Errors.invalidRefreshToken.message}" error`, function (done) {
                const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                const invalidToken = {
                    tok: props.refreshToken.refresh.tok,
                    exp: props.refreshToken.refresh.exp,
                    pl: lastJwtPayload
                };

                //  change first character to a different one
                const [salt, token] = invalidToken.tok.split('.');
                const newSalt = String.fromCharCode((salt.charCodeAt(0) + 1) % 255) + salt.slice(1);
                invalidToken.tok = `${newSalt}.${token}`;

                emitEvent(props.socket, Events.authRefreshTokenExchange, invalidToken, (err, newRefreshToken) => {
                    testError(Errors.invalidRefreshToken, err, newRefreshToken);
                    return done(null);
                });
            });

            expectToBeClosed(props);
        });

        describe('Tampering with the token of the refresh-token', function () {
            login(props);

            it(`Should get an "${Errors.invalidRefreshToken.message}" error`, function (done) {
                const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                const invalidToken = {
                    tok: props.refreshToken.refresh.tok,
                    exp: props.refreshToken.refresh.exp,
                    pl: lastJwtPayload
                };

                //  change first character to a different one
                const [salt, token] = invalidToken.tok.split('.');
                const newToken = String.fromCharCode((token.charCodeAt(0) + 1) % 255) + token.slice(1);
                invalidToken.tok = `${salt}.${newToken}`;

                emitEvent(props.socket, Events.authRefreshTokenExchange, invalidToken, (err, newRefreshToken) => {
                    testError(Errors.invalidRefreshToken, err, newRefreshToken);
                    return done(null);
                });
            });

            expectToBeClosed(props);
        });

        describe('Tampering with the expiration of the refresh-token', function () {
            login(props);

            it(`Should get an "${Errors.invalidRefreshToken.message}" error`, function (done) {
                const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                const invalidToken = {
                    tok: props.refreshToken.refresh.tok,
                    exp: props.refreshToken.refresh.exp + 10000,
                    pl: lastJwtPayload
                };

                emitEvent(props.socket, Events.authRefreshTokenExchange, invalidToken, (err, newRefreshToken) => {
                    testError(Errors.invalidRefreshToken, err, newRefreshToken);
                    return done(null);
                });
            });

            expectToBeClosed(props);
        });

        describe('Sending a malformed JWT payload (bad JSON)', function () {
            login(props);

            it(`Should get an "${Errors.validationError.message}" error`, function (done) {
                const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                const invalidToken = {
                    tok: props.refreshToken.refresh.tok,
                    exp: props.refreshToken.refresh.exp,
                    pl: lastJwtPayload
                };

                invalidToken.pl = base64url.decode(invalidToken.pl).slice(0, -2);

                emitEvent(props.socket, Events.authRefreshTokenExchange, invalidToken, (err, newRefreshToken) => {
                    testError(Errors.validationError, err, newRefreshToken);
                    return done(null);
                });
            });

            expectToBeClosed(props);
        });

        describe('Sending invalid Base64 characters in the payload', function () {
            login(props);

            it(`Should get an "${Errors.validationError.message}" error`, function (done) {
                const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                const invalidToken = {
                    tok: props.refreshToken.refresh.tok,
                    exp: props.refreshToken.refresh.exp,
                    pl: lastJwtPayload
                };

                invalidToken.pl = '$'.concat(invalidToken.pl.slice(1));

                emitEvent(props.socket, Events.authRefreshTokenExchange, invalidToken, (err, newRefreshToken) => {
                    testError(Errors.validationError, err, newRefreshToken);
                    return done(null);
                });
            });

            expectToBeClosed(props);
        });

        describe('Using an expired refresh-token', function () {
            login(props);

            it(`Should get an "${Errors.refreshTokenHasExpired.message}" error`, function (done) {
                this.timeout(12000);
                this.slow(10000);

                async.waterfall([
                    (next) => {
                        const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');
                        //  we tweak the expiry of the tokens before starting the server
                        Config.general.refreshTokenExpiryInSecs = 3;

                        refreshAuthToken(props.socket, lastJwtPayload, props.refreshToken, (err, newRefreshToken) => {
                            if (err) {
                                return next(err);
                            }

                            const nowInSecs = Util.getDateNowInSeconds();

                            expect(newRefreshToken.refresh.exp).to.be.at.most(nowInSecs + Config.general.refreshTokenExpiryInSecs, 'Refresh-token\'s expiration time is not correct');
                            props.refreshToken = newRefreshToken;

                            return next(null);
                        });
                    },

                    (next) => {
                        const nowInSecs = Util.getDateNowInSeconds();
                        const [, lastJwtPayload] = props.socket.signedAuthToken.split('.');

                        setTimeout(() => {
                            refreshAuthToken(props.socket, lastJwtPayload, props.refreshToken, (err, newRefreshToken) => {
                                testError(Errors.refreshTokenHasExpired, err, newRefreshToken);
                                return next(null);
                            });
                        }, ((props.refreshToken.refresh.exp - nowInSecs) + 1) * 1000);
                    }
                ], err => {
                    done(err);
                });
            });

            expectToBeClosed(props);
        });
    });

    after('After hook', function (done) {
        this.timeout(5000);

        const db = Config.general.databaseName;

        const del = (DbEntity, cb) => {
            const sql = knex
                .delete()
                .from(`${db}.${DbEntity.tableName}`)
                .where(DbEntity.object)
                .toString();

            database.query(sql, err => cb(err));
        };

        async.waterfall([
            (next) => {
                async.series([
                    (cb) => del(new EmailDelete(uuidOrg, uuidUser), cb),

                    (cb) => del(new AttributeDelete(uuidOrg, uuidUser), cb),

                    (cb) => del(new PolicyDelete(uuidOrg, uuidUser), cb),
                    (cb) => del(new PolicyDelete(uuidOrg, deviceUuid), cb),
                    (cb) => del(new PolicyDelete(uuidOrg, uuidOrg), cb),
                ], err => next(err));
            },
            (next) => {
                database.stop(err => next(err));
            },
            (next) => {
                scServer.stop(err => next(err));
            }
        ], err => {
            done(err);
        });
    });
});

function login(props, msg = 'User should be successfully logged in', login = EMAIL, password = PASSWORD, errHandler = null) {
    it(msg, function (done) {
        this.timeout(1500);
        this.slow(250);

        const onConnect = (socket, status) => {
            expect(status.isAuthenticated).to.be.false;

            sendLogin(socket, login, password, (err, data) => {
                if (err && errHandler) {
                    errHandler(err, data);
                }

                props.authToken = socket.authToken;
                props.refreshToken = data;

                done(null);
            });
        };

        const onError = (socket, err) => {
            done(err);
        };

        if (props.socket) {
            props.socket.on('disconnect', () => {
                props.socket = createClientSocket(onConnect, onError);
            });

            props.socket.deauthenticate();
            props.socket.disconnect();
        } else {
            props.socket = createClientSocket(onConnect, onError);
        }
    });
}

function validateTokens(props) {
    it('Socket should be in an authenticated state', function () {
        expect(props.socket.authState).to.equal(props.socket.AUTHENTICATED);
    });

    it('Signature should be valid', function (done) {
        jwt.verify(props.socket.signedAuthToken, Config.socketCluster.options.authPublicKey, { algorithms: ['RS256'] }, err => done(err));
    });

    it('JWT should be valid', function () {
        expect(props.authToken).to.be.an('object');
        expect(props.authToken).to.have.key('context', 'sub', 'exp', 'iat');
        expect(props.authToken.context).to.deep.equal({
            org_policy_uuid: uuidOrg,
            sub_policy_type: PolicyType.strUser    //  user
        });
        expect(props.authToken.sub).to.equal(uuidUser);
    });

    it('Refresh-token should be valid', function () {
        expect(props.refreshToken).to.be.an('object');
        expect(props.refreshToken).to.have.key('refresh');
        expect(props.refreshToken.refresh).to.have.all.keys('tok', 'exp');
    });

    it('Expiration should be valid on both tokens (JWT, refresh-token)', function () {
        const nowInSecs = Util.getDateNowInSeconds();

        expect(props.refreshToken.refresh.exp).to.be.at.most(nowInSecs + Config.general.refreshTokenExpiryInSecs, 'Refresh-token\'s expiration time is not correct');
        expect(props.authToken.exp).to.be.at.most(nowInSecs + Config.general.authTokenExpiryInSecs, 'Auth-token\'s expiration time is not correct');
    });
}

function expectToBeClosed(props) {
    it('Socket should be closed at this point', function () {
        expect(props.socket.getState()).to.be.equal(props.socket.CLOSED);
        props.socket = undefined;
    });
}

function createClientSocket(connectHandler, errorHandler) {
    const options = Config.socketCluster.options;

    const socket = scClient.connect({
        port: options.port,
        hostname: options.host,
        secure: options.protocol === 'https' ? true : false,
        rejectUnauthorized: false
    });

    socket.off();

    //  event handlers with 'socket' prefixed
    socket.on('connect', connectHandler.bind(this, socket));
    socket.on('error', errorHandler.bind(this, socket));

    return socket;
}

function sendLogin(socket, login, password, cb) {
    const credentials = {
        login: login,
        password: password
    };

    emitEvent(socket, Events.authLoginWithCredentials, credentials, cb);
}

function refreshAuthToken(socket, lastJwtPayload, refreshToken, cb) {
    const payload = {
        tok: refreshToken.refresh.tok,
        exp: refreshToken.refresh.exp,
        pl: lastJwtPayload
    };

    emitEvent(socket, Events.authRefreshTokenExchange, payload, cb);
}

function emitEvent(socket, event, payload, cb) {
    socket.emit(event, payload, (err, data) => cb(err, data));
}

function testError(expectedError, incomingErr, data) {
    const errorType = type(expectedError);

    expect(data).to.be.undefined;
    expect(incomingErr).to.be.an(errorType);
    expect(incomingErr.id).to.equal(expectedError.id);
}
