/**
 * Grant constructor.
 *
 * @param grantObj object The grant object data
 */
var Grant = function(grantObj) {
	this.grant = grantObj;
};

module.exports = Grant;

/**
 * Returns the data associated with a Grant object.
 *
 * @return object The data.
 */
Grant.prototype.asObject = function() {
	return this.grant;
};

/**
 * Checks whether the grant contains the given field.
 *
 * @param k mixed Can be a string naming a dot-separated path to check for, or an array of strings,
 * or an object mapping dot-separated paths to boolean true.
 * @return boolean Whether or not the given field is contained.
 */
Grant.prototype.has = function(k) {
	var self = this;
	if(this.grant === true) return true;
	if(typeof this.grant != 'object') return false;

	function checkPath(path) {
		var parts = path.split('.');
		var cur = self.grant;
		for(var i = 0; i < parts.length; i++) {
			if(cur === true) return true;
			var part = parts[i];
			if(typeof cur != 'object' || !cur) return false;
			cur = cur[part];
		}
		return cur === true;
	}

	if(typeof k == 'string') {
		return checkPath(k);
	} else if(Array.isArray(k)) {
		for(var i = 0; i < k.length; i++) {
			if(!checkPath(k[i])) return false;
		}
		return true;
	} else if(typeof k == 'object') {
		for(var key in k) {
			if(k[key] && !checkPath(k[key])) return false;
		}
		return true;
	} else {
		return false;
	}
};

// Alias has to can
Grant.prototype.can = Grant.prototype.has;

/**
 * Returns a sub-part of a grant.  May return boolean true (if all permissions granted) or
 * boolean false (if no permission is granted) in the sub-part.
 *
 * @param k string A dot-separated path in the grant data
 * @return mixed The contents of the grant portion, or true/false
 */
Grant.prototype.get = function(k) {
	function gget(keyParts, grantObj) {
		if(grantObj === true) return true;
		if(!keyParts.length) return grantObj;
		if(typeof grantObj == 'object' && grantObj) {
			return gget(keyParts.slice(1), grantObj[keyParts[0]]);
		}
		return false;
	}
	return gget(k.split('.'), this.grant);
};

/**
 * Returns the maximum of a numeric value in a grant.
 *
 * @param k string A path in the grant
 * @return number The max, or null
 */
Grant.prototype.max = function(k) {
	var val = this.get(k);
	if(val === true) return Infinity;
	if(!val || typeof val != 'object' || !val.grantNumber || typeof val.max != 'number') return null;
	return val.max;
};

/**
 * Returns the minimum of a numeric value in a grant.
 *
 * @param k string A path in the grant
 * @return number The min, or null
 */
Grant.prototype.min = function(k) {
	var val = this.get(k);
	if(val === true) return -Infinity;
	if(!val || typeof val != 'object' || !val.grantNumber || typeof val.min != 'number') return null;
	return val.min;
};

/**
 * Returns a mask/whitelist at the given path in the grant.
 *
 * @param k string A path in the grant
 * @return mixed The mask at that path in the grant (can be boolean true or false as well)
 */
Grant.prototype.getMask = function(k) {
	var mask = this.get(k);
	if(mask !== true && typeof mask != 'object') return false;
	return mask;
};

/**
 * Combines multiple grants together.
 *
 * @param grant1...n mixed Grant object contents to combine (not Grant objects, the actual data)
 * @return object The combined grant
 */
function combineGrants() {
	function grantType(grant) {
		if(grant === true) return 'true';
		if(typeof grant == 'object' && grant && grant.grantNumber) return 'grantnum';
		if(typeof grant == 'object' && grant) return 'object';
		return 'false';
	}
	function combine2(grant1, grant2) {
		var type1 = grantType(grant1);
		var type2 = grantType(grant2);
		if(type1 == 'true' || type2 == 'true') return true;
		if(type1 == 'false') return grant2;
		if(type2 == 'false') return grant1;
		if(type1 == 'object' && type2 == 'object') {
			var newObj = {};
			var allKeySet = {};
			Object.keys(grant1).concat(Object.keys(grant2)).forEach(function(k) { allKeySet[k] = true; });
			Object.keys(allKeySet).forEach(function(k) {
				if(grant1[k] === undefined) newObj[k] = grant2[k];
				else if(grant2[k] === undefined) newObj[k] = grant1[k];
				else newObj[k] = combine2(grant1[k], grant2[k]);
			});
			return newObj;
		}
		if(type1 == 'grantnum' && type2 == 'grantnum') {
			return {
				grantNumber: true,
				min: Math.min(grant1.min, grant2.min),
				max: Math.max(grant1.max, grant2.max)
			};
		}
		if(type1 == 'object') return grant1;
		if(type2 == 'object') return grant2;
		return false;
	}
	if(!arguments.length) return false;
	else if(arguments.length == 1) return arguments[0];
	else return Array.prototype.slice.call(arguments, 0).reduce(function(accum, cur) {
		return combine2(accum, cur);
	}, false);
}

Grant.combineGrants = combineGrants;


// Internal function that processes numeric grant entries into min/max objects
function grantNumbersToObjects(grantObj) {
	if(grantObj && typeof grantObj == 'object' && !grantObj.grantNumber) {
		var newObj = {};
		Object.keys(grantObj).forEach(function(k) {
			newObj[k] = grantNumbersToObjects(grantObj[k]);
		});
		return newObj;
	} else if(typeof grantObj == 'number') {
		return {
			grantNumber: true,
			min: grantObj,
			max: grantObj
		};
	} else {
		return grantObj;
	}
}

Grant.grantNumbersToObjects = grantNumbersToObjects;
