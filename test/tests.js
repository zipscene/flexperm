// Copyright 2016 Zipscene, LLC
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

let expect = require('chai').expect;
let PermissionSet = require('../lib/index');
let objtools = require('objtools');
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

	it('permission vars', function() {
		let permissions = [ {
			target: 'Order',
			match: {
				userId: {
					$var: 'userId'
				}
			},
			grant: {
				start: true
			}
		} ];
		let permissionSet = new PermissionSet(permissions, { userId: 'asdfasdf' });
		testGrantValue(permissionSet.getTargetGrant('Order', { userId: 'asdfasdf' }), { start: true });
		testGrantValue(permissionSet.getTargetGrant('Order', { userId: 'aoeuaoeu' }), false);
	});

	it('should return an array of permissions with sustituted vars', function() {
		let permissions = [ {
			target: 'Order',
			match: {
				userId: {
					$var: 'userId'
				},
				brandId: {
					$var: 'brandId'
				}
			},
			grant: {
				start: true
			}
		} ];
		let permissionSet = new PermissionSet(permissions, { userId: 'asdfasdf', brandId: 'marcos' });
		let permissionArr = permissionSet.asArray();
		expect(permissionArr).to.have.length(1);
		expect(permissionArr[0]).to.have.property('target', 'Order');
		expect(permissionArr[0].grant).to.have.property('start', true);
		expect(permissionArr[0].match).to.have.property('userId', 'asdfasdf');
		expect(permissionArr[0].match).to.have.property('brandId', 'marcos');
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

describe('Grant', function() {

	function createGrant(grantObj) {
		return new PermissionSet.Grant(grantObj, 'LiterallyWhoCares', { personWhoCares: null });
	}

	it('accessors: asObject(), getTarget(), getMatch()', function() {
		let grantObj = { read: true };
		let grant = createGrant(grantObj);
		expect(grant.asObject()).to.deep.equal(grantObj);
		expect(grant.getTarget()).to.equal('LiterallyWhoCares');
		expect(grant.getMatch()).to.deep.equal({ personWhoCares: null });
	});

	it('combineGrants()', function() {
		let grant1 = {
			read: true,
			readMask: {
				thing: true,
				thang: {
					_: true,
					subThang: false
				},
				thung: {
					subThung: true
				}
			}
		};
		let grant2 = {
			read: true,
			query: true,
			readMask: {
				thang: true,
				thung: {
					subberThung: true
				}
			}
		};
		let combined = PermissionSet.Grant.combineGrants(grant1, grant2);
		expect(combined).to.deep.equal({
			read: true,
			query: true,
			readMask: {
				thang: true,
				thing: true,
				thung: {
					subThung: true,
					subberThung: true
				}
			}
		});
	});

	it('createSubgrantFromMask()', function() {
		let grant = createGrant({
			do: true,
			dont: {
				doThis: true
			}
		});
		expect(grant.createSubgrantFromMask('dont').asObject()).to.deep.equal({ doThis: true });
	});

	it('has(), check()', function() {

		function checkBoth(shouldSucceed, grant, hasArg) {
			if (shouldSucceed) {
				expect(grant.has(hasArg)).to.equal(true);
				expect(grant.check(hasArg)).to.equal(true);
			} else {
				expect(grant.has(hasArg)).to.equal(false);
				expect(function() {
					grant.check(hasArg);
				}).to.throw(XError);
			}
		}

		let grant1 = createGrant({
			this: true,
			andThis: true,
			whatAboutThese: {
				_: true,
				butNotThis: false
			}
		});
		checkBoth(true, grant1, 'andThis');
		checkBoth(false, grant1, 'howAboutThis');
		checkBoth(true, grant1, 'whatAboutThese.yeahThisToo');
		checkBoth(false, grant1, 'whatAboutThese.butNotThis');

		let grant2 = createGrant(true);
		checkBoth(true, grant2, 'evenThis');
		checkBoth(true, grant2, 'this.and.this.and.literally.everything');

		let grant3 = createGrant(false);
		checkBoth(false, grant3, 'awcmonjustalittle');
	});

	it('checkMask()', function() {
		let grant = createGrant({
			update: true,
			updateMask: {
				always: true,
				stillAlways: true,
				sometimes: {
					_: true,
					justNotNow: false
				}
			}
		});
		let obj = {
			always: 'hi',
			stillAlways: 'bye',
			sometimes: {
				stillThinkWereGood: 'cry'
			}
		};
		expect(grant.checkMask('updateMask', obj)).to.equal(true);
		obj.sometimes.justNotNow = 'try';
		expect(function() {
			grant.checkMask('updateMask', obj);
		}).to.throw(XError);
	});

	it('checkNumber()', function() {
		let grant = createGrant({
			notNumber: true,
			number: {
				grantNumber: true,
				min: 0,
				max: 10
			},
			moreNumber: {
				grantNumber: true,
				min: 0,
				max: true
			}
		});
		expect(function() {
			grant.checkNumber('hopefullyNumber', 5);
		}).to.throw(XError);
		expect(grant.checkNumber('notNumber', 50000)).to.equal(true);
		expect(grant.checkNumber('number', 8)).to.equal(true);
		expect(function() {
			grant.checkNumber('number', -2);
		}).to.throw(XError);
		expect(function() {
			grant.checkNumber('number', 13);
		}).to.throw(XError);
		expect(grant.checkNumber('moreNumber', 0)).to.equal(true);
		expect(grant.checkNumber('moreNumber', 15)).to.equal(true);
	});

});
