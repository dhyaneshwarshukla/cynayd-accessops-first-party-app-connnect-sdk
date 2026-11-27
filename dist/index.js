"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.oneSigningKeys = exports.FirstPartyAuthError = exports.configuredInstallation = exports.checkApplicationAccess = exports.applicationAuthorizationEnabled = exports.ApplicationAccessError = void 0;
var application_authorization_1 = require("./application-authorization");
Object.defineProperty(exports, "ApplicationAccessError", { enumerable: true, get: function () { return application_authorization_1.ApplicationAccessError; } });
Object.defineProperty(exports, "applicationAuthorizationEnabled", { enumerable: true, get: function () { return application_authorization_1.applicationAuthorizationEnabled; } });
Object.defineProperty(exports, "checkApplicationAccess", { enumerable: true, get: function () { return application_authorization_1.checkApplicationAccess; } });
Object.defineProperty(exports, "configuredInstallation", { enumerable: true, get: function () { return application_authorization_1.configuredInstallation; } });
__exportStar(require("./delegation/client"), exports);
__exportStar(require("./delegation/signer"), exports);
__exportStar(require("./delegation/session"), exports);
__exportStar(require("./delegation/resource"), exports);
var transport_1 = require("./delegation/transport");
Object.defineProperty(exports, "FirstPartyAuthError", { enumerable: true, get: function () { return transport_1.FirstPartyAuthError; } });
var jwks_1 = require("./delegation/jwks");
Object.defineProperty(exports, "oneSigningKeys", { enumerable: true, get: function () { return jwks_1.oneSigningKeys; } });
__exportStar(require("./delegation/renewal"), exports);
__exportStar(require("./delegation/lifecycle"), exports);
//# sourceMappingURL=index.js.map