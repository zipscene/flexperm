let XError = require('xerror');
let objtools = require('zs-objtools');


class Grant {

	/**
	 * Grant constructor.
	 *
	 * @param grantObj object The grant object data
	 * @param target string Optional target used to generate the grant
	 * @param match object Optional match used to generate the grant
	 */
	constructor(grantObj, target, match) {
		this.grant = grantObj;
		this._target = target;
		this._match = match;
	}

	getTarget() {
		return this._target;
	}

	getMatch() {
		return this._match;
	}

	createSubgrantFromMask(mask) {
		if (typeof mask === 'string') {
			mask = this.getMask(mask);
		}
		return new Grant(mask, this._target, this._match);
	}

	createSubgrantFromMasks(masks) {
		let maskObjs = [];
		for (let i = 0; i < masks.length; i++) {
			if (typeof masks[i] === 'string') {
				maskObjs.push(this.getMask(masks[i]));
			} else {
				maskObjs.push(masks[i]);
			}
		}
		let mask = Grant.combineGrants(maskObjs);
		return new Grant(mask, this._target, this._match);
	}

	/**
	 * Returns the data associated with a Grant object.
	 *
	 * @return object The data.
	 */
	asObject() {
		return this.grant;
	}

	/**
	 * Checks whether the grant contains the given field.
	 *
	 * @param k mixed Can be a string naming a dot-separated path to check for, or an array of strings,
	 * or an object mapping dot-separated paths to boolean true.
	 * @return boolean Whether or not the given field is contained.
	 */
	has(k, prefix) {
		if (!prefix) prefix = '';
		let self = this;
		if (this.grant === true) return true;
		if (typeof this.grant !== 'object') return false;

		function checkPath(path) {
			return objtools.checkMaskPath(self.grant, path);
		}

		if (typeof k === 'string') {
			return checkPath(prefix + k);
		} else if (Array.isArray(k)) {
			for (let i = 0; i < k.length; i++) {
				if (!checkPath(prefix + k[i])) return false;
			}
			return true;
		} else if (typeof k === 'object' && k) {
			for (let key in k) {
				if (k[key] && !checkPath(prefix + k[key])) return false;
			}
			return true;
		} else {
			return false;
		}
	}

	// Like has(), but returns null on success and an instance of XError on failure
	// Prefer to use this instead of has() if possible so errors are returned in a consistent format
	check(k, prefix) {
		if (!prefix) prefix = '';
		if (typeof k === 'string') {
			if (!this.has(k, prefix)) {
				if (this._target) {
					return new XError(XError.ACCESS_DENIED,
						'Access denied trying to ' + prefix + k + ' a target of type ' + this._target,
						{ grantKey: prefix + k, target: this._target, match: this._match }
					);
				} else {
					return new XError(XError.ACCESS_DENIED, 'Access denied trying to ' + prefix + k);
				}
			}
		} else if (Array.isArray(k)) {
			for (let i = 0; i < k.length; i++) {
				let e = this.check(k[i], prefix);
				if (e) return e;
			}
		} else if (typeof k === 'object' && k) {
			for (let key in k) {
				let e2 = this.check(key, prefix);
				if (e2) return e2;
			}
		} else {
			return new XError(XError.INTERNAL_ERROR,
				'Supplied invalid key to permission checking function',
				{ key: k }
			);
		}
		return null;
	}

	/**
	 * Checks an object against a mask that's a subcomponent of this grant.  If any field is in the object
	 * that is not matched by the grant, this returns a XError.  Otherwisee, it returns null.
	 * The mask argument can either be a mask object or a string path to a mask in this grant.
	 */
	checkMask(mask, obj) {
		let maskPath = null;
		if (typeof mask === 'string') {
			maskPath = mask;
			mask = this.getMask(maskPath);
		}

		if (mask === true) return null;
		if (!mask) {
			return new XError(XError.ACCESS_DENIED,
				'Access denied in ' + (maskPath || 'mask') + ' for objects of type ' + this._target,
				{ grantKey: maskPath, target: this._target, match: this._match }
			);
		}
		if (!obj || typeof obj !== 'object') {
			return new XError(XError.INTERNAL_ERROR, 'Tried to do permissions match against non-object');
		}

		let maskedOutFields = objtools.getMaskedOutFields(obj, mask);
		if (maskedOutFields.length) {
			return new XError(XError.ACCESS_DENIED,
				'Access denied in ' + (maskPath || 'mask') + ' for objects of type ' +
					this._target + ' to access field ' + maskedOutFields[0],
				{ grantKey: maskPath, target: this._target, match: this._match }
			);
		}
		return null;
	}

	/**
	 * Returns a sub-part of a grant.  May return boolean true (if all permissions granted) or
	 * boolean false (if no permission is granted) in the sub-part.
	 *
	 * @param k string A dot-separated path in the grant data
	 * @return mixed The contents of the grant portion, or true/false
	 */
	get(k) {
		function gget(keyParts, grantObj) {
			if (grantObj === true) return true;
			if (!keyParts.length) return grantObj;
			if (typeof grantObj === 'object' && grantObj) {
				return gget(keyParts.slice(1), grantObj[keyParts[0]]);
			}
			return false;
		}
		return gget(k.split('.'), this.grant);
	}

	/**
	 * Returns the maximum of a numeric value in a grant.
	 *
	 * @param k string A path in the grant
	 * @return number The max, or null
	 */
	max(k) {
		let val = this.get(k);
		if (val === true) return Infinity;
		if (!val || typeof val !== 'object' || !val.grantNumber || typeof val.max !== 'number') return null;
		return val.max;
	}

	/**
	 * Returns the minimum of a numeric value in a grant.
	 *
	 * @param k string A path in the grant
	 * @return number The min, or null
	 */
	min(k) {
		let val = this.get(k);
		if (val === true) return -Infinity;
		if (!val || typeof val !== 'object' || !val.grantNumber || typeof val.min !== 'number') return null;
		return val.min;
	}

	/**
	 * Returns a mask/whitelist at the given path in the grant.
	 *
	 * @param k string A path in the grant
	 * @return mixed The mask at that path in the grant (can be boolean true or false as well)
	 */
	getMask(k) {
		let mask = this.get(k);
		if (mask !== true && typeof mask !== 'object') return false;
		return mask;
	}

	/**
	 * Combines this grant with the given other grant.  The result overwrites this grant's data.
	 */
	combine(otherGrant) {
		this.grant = Grant.combineGrants(this.grant, otherGrant.grant);
	}


	/**
	 * Combines multiple grants together.
	 *
	 * @param grant1...n mixed Grant object contents to combine (not Grant objects, the actual data)
	 * @return object The combined grant
	 */
	// This code is copied and modified from objtools addMasks() function
	static combineGrants() {
		let resultMask = false;

		// Adds a single mask (fromMask) into the resultMask mask in-place.  toMask should be an object.
		// If the resulting mask is a boolean true, this function returns true.  Otherwise, it returns toMask.
		function addMask(resultMask, newMask) {
			let key;

			if (resultMask === true) return true;
			if (newMask === true) {
				resultMask = true;
				return resultMask;
			}
			if (objtools.isScalar(newMask)) return resultMask;
			if (objtools.isScalar(resultMask)) {
				resultMask = objtools.deepCopy(newMask);
				return resultMask;
			}

			if (Array.isArray(resultMask)) {
				resultMask = { _: resultMask[0] || false };
			}
			if (Array.isArray(newMask)) {
				newMask = { _: newMask[0] || false };
			}

			// Handle the case of grant numbers
			if (resultMask.grantNumber && newMask.grantNumber) {
				resultMask.min = Math.min(resultMask.min, newMask.min);
				resultMask.max = Math.max(resultMask.max, newMask.max);
				return resultMask;
			} else if (resultMask.grantNumber || newMask.grantNumber) {
				return false;	// Mismatched types ... can't really handle it better
			}

			// If there are keys that exist in result but not in the newMask,
			// and the result mask has a _ key (wildcard), combine
			// the wildcard mask with the new mask, because in the existing result mask,
			// that key has the wildcard permissions
			if (newMask._ !== undefined) {
				for (key in resultMask) {
					if (key === '_') continue;
					if (newMask[key] === undefined) {
						resultMask[key] = addMask(resultMask[key], newMask._);
					}
				}
			}

			// same here ... also, copy over or merge fields
			for (key in newMask) {
				if (key === '_') continue;
				if (resultMask[key] !== undefined) {
					resultMask[key] = addMask(resultMask[key], newMask[key]);
				} else if (resultMask._ !== undefined) {
					resultMask[key] = addMask(objtools.deepCopy(newMask[key]), resultMask._);
				} else {
					resultMask[key] = objtools.deepCopy(newMask[key]);
				}
			}
			// fill in the _ key that we skipped earlier
			if (newMask._ !== undefined) {
				if (resultMask._ !== undefined) resultMask._ = addMask(resultMask._, newMask._);
				else resultMask._ = objtools.deepCopy(newMask._);
			}

			return resultMask || false;
		}

		for (let argIdx = 0; argIdx < arguments.length; argIdx++) {
			resultMask = addMask(resultMask, arguments[argIdx]);
			if (resultMask === true) return true;
		}
		return resultMask || false;
	}

	static grantNumbersToObjects(grantObj) {
		if (grantObj && typeof grantObj === 'object' && !grantObj.grantNumber) {
			let newObj = {};
			Object.keys(grantObj).forEach(function(k) {
				newObj[k] = Grant.grantNumbersToObjects(grantObj[k]);
			});
			return newObj;
		} else if (typeof grantObj === 'number') {
			return {
				grantNumber: true,
				min: grantObj,
				max: grantObj
			};
		} else {
			return grantObj;
		}
	}

}

module.exports = Grant;
