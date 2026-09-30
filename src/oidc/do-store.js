// OIDC provider state in a Durable Object — see ../stores/do.js for what that buys and how to set
// the object up. Every operation is a single call into one object, so code redemption and refresh
// rotation are atomic exactly as they are in D1OidcStore (which supplies the SQL).

import { OIDC_METHODS, storageStub } from "../stores/do.js";

export class DoOidcStore {
  /**
   * @param {DurableObjectNamespace} binding  e.g. `env.QRAUTH_DO`.
   * @param {object} [options]
   * @param {string} [options.name="default"]  Object name. Sharing it with DoLoginStore is fine.
   */
  constructor(binding, { name = "default" } = {}) {
    storageStub(binding, name);
    this.binding = binding;
    this.name = name;
  }
}

for (const method of OIDC_METHODS) {
  DoOidcStore.prototype[method] = function (...args) {
    return storageStub(this.binding, this.name)[`oidc_${method}`](...args);
  };
}
