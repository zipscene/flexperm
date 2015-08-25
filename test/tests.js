let expect = require('chai').expect;
let PermissionSet = require('../lib/index');
let objtools = require('zs-objtools');
let XError = require('xerror');


function testGrantValue(grant, expectedValue) {
	expect(grant.asObject()).to.deep.equal(expectedValue);
}

describe('Permissions', function() {

	let bigPermissions = [ {
		target: 'pet',
		match: {
			animalType: 'dog'
		},
		grant: {
			feed: true,
			play: true
		}
	}, {
		target: 'pet',
		match: {
			cute: true
		},
		grant: {
			walk: true
		}
	}, {
		target: 'food',
		match: {
			owned: true,
			type: { $ne: 'cheese' }
		},
		grant: {
			eat: true
		}
	} ];
	let bigPermissionSet = new PermissionSet(bigPermissions);  // Don't mutate this please :)
	let adminPermissionSet = new PermissionSet([ {
		target: '*',
		match: {},
		grant: true
	} ]);

	it('can construct a permission set', function() {
		expect(function() {
			return new PermissionSet([]);
		}).to.not.throw(Error);
	});

	it('asArray()', function() {
		let permissions = [ {
			name: 'Tama',
			animalType: 'cat',
			grant: true
		} ];
		expect(new PermissionSet(permissions).asArray()).to.deep.equal(permissions);
	});

	it('simple getTargetGrant()', function() {
		let pet1 = {
			name: 'Tama',
			animalType: 'cat'
		};
		let pet2 = {
			name: 'Howard',
			animalType: 'duck'
		};
		let permissions = [ {
			target: 'pet',
			match: {
				animalType: 'cat'
			},
			grant: {
				feed: true,
				play: true
			}
		} ];
		let permissionSet = new PermissionSet(permissions);
		testGrantValue(permissionSet.getTargetGrant('pet', pet1), {
			feed: true,
			play: true
		});
		testGrantValue(permissionSet.getTargetGrant('cutepet', pet1), false);
		testGrantValue(permissionSet.getTargetGrant('pet', pet2), false);
	});

	it('getTargetGrant() accepts query operators', function() {
		let food1 = {
			owned: true,
			type: 'chicken'
		};
		let food2 = {
			owned: true,
			type: 'cheese'
		};
		testGrantValue(bigPermissionSet.getTargetGrant('food', food1), { eat: true });
		testGrantValue(bigPermissionSet.getTargetGrant('food', food2), false);
	});

	it('getTargetGrant() combines grants when applicable', function() {
		let pet1 = {
			name: 'Howard',
			animalType: 'duck'
		};
		let pet2 = {
			name: 'Fowler',
			animalType: 'duck'
		};
		let permissions = [ {
			target: 'pet',
			match: {
				animalType: 'duck'
			},
			grant: {
				feed: true
			}
		}, {
			target: 'pet',
			match: {
				animalType: 'duck',
				name: 'Howard'
			},
			grant: {
				play: true
			}
		} ];
		let permissionSet = new PermissionSet(permissions);
		testGrantValue(permissionSet.getTargetGrant('pet', pet1), {
			feed: true,
			play: true
		});
		testGrantValue(permissionSet.getTargetGrant('pet', pet2), {
			feed: true
		});
	});

	it('getTargetGrant() on admin permission', function() {
		let weirdObject = {
			daiofj: 'adoifam',
			asdfasdfasdf: 4
		};
		testGrantValue(adminPermissionSet.getTargetGrant('thingy??', weirdObject), true);
	});

	it('rebuild()', function() {
		let pet = {
			name: 'Harriet',
			animalType: 'dodo'
		};
		let permissions = [ {
			target: 'pet',
			match: {
				name: 'Joanna',
				animalType: 'dodo'
			},
			grant: {
				walk: true
			}
		} ];
		let permissionSet = new PermissionSet(permissions);
		testGrantValue(permissionSet.getTargetGrant('pet', pet), false);
		permissionSet.asArray()[0].match.name = 'Harriet';
		permissionSet.rebuild();
		testGrantValue(permissionSet.getTargetGrant('pet', pet), {
			walk: true
		});
	});

	it('getTargetQueryFields()', function() {
		expect(bigPermissionSet.getTargetQueryFields('pet')).to.deep.equal([
			'animalType',
			'cute'
		]);
		expect(bigPermissionSet.getTargetQueryFields('food')).to.deep.equal([
			'owned',
			'type'
		]);
	});

	it('getHash()', function() {
		expect(bigPermissionSet.getHash()).to.equal(bigPermissionSet.getHash());
		expect(bigPermissionSet.getHash()).to.not.equal(adminPermissionSet.getHash());
	});

	it('serialize() and deserialize()', function() {
		let serialized = bigPermissionSet.serialize();
		let newPermissionSet = PermissionSet.deserialize(serialized);
		expect(newPermissionSet.asArray()).to.deep.equal(bigPermissions);
	});

	it('createFilterByMask()', function() {
		let permissions = [ {
			target: 'Army',
			match: {
				nationality: 'French'
			},
			grant: {
				engageInGloriousBattle: true,
				engageInGloriousBattleMask: {
					infantry: true,
					cavalry: true
				}
			}
		} ];
		let permissionSet = new PermissionSet(permissions);
		let filterFunc = permissionSet.createFilterByMask('Army', 'engageInGloriousBattle',
			'engageInGloriousBattleMask'
		);
		let army1 = {
			nationality: 'French',
			infantry: 20000,
			cavalry: 40000,
			airforce: 2
		};
		let army2 = {
			nationality: 'Atlantean',
			infantry: 0,
			cavalry: 0,
			airforce: 0
		};
		expect(filterFunc(army1)).to.deep.equal({
			infantry: 20000,
			cavalry: 40000
		});
		expect(filterFunc(army2)).to.equal(null);
	});

	it('checkExecuteQuery()', function() {
		let permission = {
			target: 'User',
			match: {},
			grant: {
				read: true,
				query: true,
				doSomething: true,
				readMask: {
					name: true,
					age: true,
					email: true,
					secretData: {
						_: true,
						password: false
					}
				},
				maxQueryLimit: {
					grantNumber: true,
					min: true,
					max: 100
				}
			}
		};
		let permissionSet = new PermissionSet([ permission ]);
		let query = {
			name: 'Bob',
			age: { $gt: 21 },
			'secretData.shhItsASecret': 'asdfasdfasdfasdf'
		};

		expect(permissionSet.checkExecuteQuery('User', query)).to.equal(true);
		// Invalidate query a couple of ways
		let badQuery = objtools.deepCopy(query);
		badQuery['secretData.password'] = 'password';
		expect(function() {
			permissionSet.checkExecuteQuery('User', badQuery);
		}).to.throw(XError);
		expect(function() {
			permissionSet.checkExecuteQuery('MegaUser', query);
		}).to.throw(XError);
		// Test opts to checkExecuteQuery
		expect(permissionSet.checkExecuteQuery('User', query, {
			fields: [ 'name', 'age', 'secretData.illNeverTell' ],
			sort: [ 'age' ],
			limit: 50
		}, 'doSomething')).to.equal(true);
		expect(function() {
			permissionSet.checkExecuteQuery('User', query, { fields: [ 'name', 'gender' ] });
		}).to.throw(XError);
		expect(function() {
			permissionSet.checkExecuteQuery('User', query, { sort: [ 'birthday' ] });
		}).to.throw(XError);
		expect(function() {
			permissionSet.checkExecuteQuery('User', query, { limit: 101 });
		}).to.throw(XError);
		expect(function() {
			permissionSet.checkExecuteQuery('User', query, null, 'doSomethingElse');
		}).to.throw(XError);
	});

});

describe('Legacy permission conversion', function() {

	it('fromLegacyPermissions()', function() {
		let legacyPermissions = [ {
			type: 'target',
			targetType: 'User',
			target: {
				ns: 'brand_zcafe'
			},
			grant: true
		} ];
		let permissionSet = PermissionSet.fromLegacyPermissions(legacyPermissions);
		testGrantValue(permissionSet.getTargetGrant('User', { ns: 'brand_zcafe' }), true);
		testGrantValue(permissionSet.getTargetGrant('Snoozer', { ns: 'brand_zcafe' }), false);
		testGrantValue(permissionSet.getTargetGrant('User', { ns: 'brand_bbbb' }), false);
	});
});
