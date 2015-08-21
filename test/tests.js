let expect = require('chai').expect;
let PermissionSet = require('../lib/index');



describe('Permissions', function() {

	function testGrantValue(grant, expectedValue) {
		expect(grant.asObject()).to.deep.equal(expectedValue);
	}

	it('can construct a permission set', function() {
		expect(function() {
			return new PermissionSet([]);
		}).to.not.throw(Error);
	});

	it('simple getTargetGrant', function() {
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

});
