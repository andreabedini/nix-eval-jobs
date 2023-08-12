#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <queue>
#include <ranges>
#include <string>
#include <thread>

#include <nix/config.h>
#include <nix/shared.hh>
#include <nix/store-api.hh>
#include <nix/eval.hh>
#include <nix/eval-inline.hh>
#include <nix/util.hh>
#include <nix/get-drvs.hh>
#include <nix/globals.hh>
#include <nix/common-eval-args.hh>
#include <nix/flake/flakeref.hh>
#include <nix/flake/flake.hh>
#include <nix/attr-path.hh>
#include <nix/derivations.hh>
#include <nix/local-fs-store.hh>
#include <nix/logging.hh>
#include <nix/error.hh>
#include <nix/installables.hh>
#include <nix/path-with-outputs.hh>
#include <nix/installable-flake.hh>
#include <nix/ref.hh>

#include <nix/value-to-json.hh>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include <nlohmann/json.hpp>

using namespace nix;
using namespace nlohmann;

// Safe to ignore - the args will be static.
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#elif __clang__
#pragma clang diagnostic ignored "-Wnon-virtual-dtor"
#endif
struct MyArgs : MixEvalArgs, MixCommonArgs {
    std::string expr;
    Path gcRootsDir;
    bool flake = false;
    bool fromArgs = false;
    bool meta = false;
    bool showTrace = false;
    bool impure = false;
    bool forceRecurse = false;
    bool checkCacheStatus = false;
    size_t nrWorkers = 1;
    size_t maxMemorySize = 4096;

    MyArgs() : MixCommonArgs("nix-eval-jobs") {
        addFlag({
            .longName = "help",
            .description = "show usage information",
            .handler = {[&]() {
                printf("USAGE: nix-eval-jobs [options] expr\n\n");
                for (const auto &[name, flag] : longFlags) {
                    if (hiddenCategories.count(flag->category)) {
                        continue;
                    }
                    printf("  --%-20s %s\n", name.c_str(),
                           flag->description.c_str());
                }
                ::exit(0);
            }},
        });

        addFlag({.longName = "impure",
                 .description = "allow impure expressions",
                 .handler = {&impure, true}});

        addFlag(
            {.longName = "force-recurse",
             .description = "force recursion (don't respect recurseIntoAttrs)",
             .handler = {&forceRecurse, true}});

        addFlag({.longName = "gc-roots-dir",
                 .description = "garbage collector roots directory",
                 .labels = {"path"},
                 .handler = {&gcRootsDir}});

        addFlag({.longName = "workers",
                 .description = "number of evaluate workers",
                 .labels = {"workers"},
                 .handler = {
                     [=, this](std::string s) { nrWorkers = std::stoi(s); }}});

        addFlag(
            {.longName = "max-memory-size",
             .description =
                 "maximum evaluation memory size (4GiB per worker by default)",
             .labels = {"size"},
             .handler = {
                 [=, this](std::string s) { maxMemorySize = std::stoi(s); }}});

        addFlag({.longName = "flake",
                 .description = "build a flake",
                 .handler = {&flake, true}});

        addFlag({.longName = "meta",
                 .description = "include derivation meta field in output",
                 .handler = {&meta, true}});

        addFlag(
            {.longName = "check-cache-status",
             .description =
                 "Check if the derivations are present locally or in "
                 "any configured substituters (i.e. binary cache). The "
                 "information "
                 "will be exposed in the `isCached` field of the JSON output.",
             .handler = {&checkCacheStatus, true}});

        addFlag({.longName = "show-trace",
                 .description =
                     "print out a stack trace in case of evaluation errors",
                 .handler = {&showTrace, true}});

        addFlag({.longName = "expr",
                 .shortName = 'E',
                 .description = "treat the argument as a Nix expression",
                 .handler = {&fromArgs, true}});

        expectArg("expr", &expr);
    }
};

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#elif __clang__
#pragma clang diagnostic ignored "-Wnon-virtual-dtor"
#endif

static MyArgs myArgs;

static Value *topLevelValue(ref<EvalState> state, Bindings &autoArgs) {
    if (myArgs.flake) {
        auto [flakeRef, fragment, outputSpec] =
            parseFlakeRefWithFragmentAndExtendedOutputsSpec(myArgs.expr,
                                                            absPath("."));

        InstallableFlake flake{{},
                               state,
                               std::move(flakeRef),
                               fragment,
                               outputSpec,
                               {},
                               {},
                               flake::LockFlags{
                                   .updateLockFile = false,
                                   .useRegistries = false,
                                   .allowUnlocked = false,
                               }};

        return flake.toValue(*state).first;
    } else if (myArgs.fromArgs) {
        Value *vRoot = state->allocValue();
        Expr *e = state->parseExprFromString(
            myArgs.expr, state->rootPath(CanonPath::fromCwd()));
        state->eval(e, *vRoot);
        return vRoot;
    } else {
        Value *vRoot = state->allocValue();
        state->evalFile(lookupFileArg(*state, myArgs.expr), *vRoot);
        return vRoot;
    }
}

bool queryIsCached(Store &store, std::map<std::string, std::string> &outputs) {
    uint64_t downloadSize, narSize;
    StorePathSet willBuild, willSubstitute, unknown;

    std::vector<StorePathWithOutputs> paths;
    for (auto const &[key, val] : outputs) {
        paths.push_back(followLinksToStorePathWithOutputs(store, val));
    }

    store.queryMissing(toDerivedPaths(paths), willBuild, willSubstitute,
                       unknown, downloadSize, narSize);
    return willBuild.empty() && unknown.empty();
}

/* The fields of a derivation that are printed in json form */
struct Drv {
    std::string name;
    std::string system;
    std::string drvPath;
    bool isCached;
    std::map<std::string, std::string> outputs;
    std::map<std::string, std::set<std::string>> inputDrvs;
    std::optional<nlohmann::json> meta;
};

// printValueAsJSON prevents EvalState const&
Drv mkDrv(EvalState &state, DrvInfo &drvInfo) {
    Drv drv;

    if (drvInfo.querySystem() == "unknown")
        throw EvalError("derivation must have a 'system' attribute");

    auto localStore = state.store.dynamic_pointer_cast<LocalFSStore>();

    try {
        for (auto out : drvInfo.queryOutputs(true)) {
            if (out.second)
                drv.outputs[out.first] =
                    localStore->printStorePath(*out.second);
        }
    } catch (const std::exception &e) {
        throw EvalError("derivation must have valid outputs: %s", e.what());
    }

    if (myArgs.meta) {
        nlohmann::json meta_;
        for (auto &metaName : drvInfo.queryMetaNames()) {
            NixStringContext context;
            std::stringstream ss;

            auto metaValue = drvInfo.queryMeta(metaName);
            // Skip non-serialisable types
            // TODO: Fix serialisation of derivations to store paths
            if (metaValue == 0) {
                continue;
            }

            printValueAsJSON(state, true, *metaValue, noPos, ss, context);

            meta_[metaName] = nlohmann::json::parse(ss.str());
        }
        drv.meta = meta_;
    }
    if (myArgs.checkCacheStatus) {
        drv.isCached = queryIsCached(*localStore, drv.outputs);
    }

    drv.name = drvInfo.queryName();
    drv.system = drvInfo.querySystem();
    drv.drvPath = localStore->printStorePath(drvInfo.requireDrvPath());

    auto _drv = localStore->readDerivation(drvInfo.requireDrvPath());
    for (auto &input : _drv.inputDrvs) {
        drv.inputDrvs[localStore->printStorePath(input.first)] = input.second;
    }

    return drv;
}

static void to_json(nlohmann::json &json, const Drv &drv) {
    json = nlohmann::json{{"name", drv.name},
                          {"system", drv.system},
                          {"drvPath", drv.drvPath},
                          {"outputs", drv.outputs},
                          {"inputDrvs", drv.inputDrvs}};

    if (drv.meta.has_value()) {
        json["meta"] = drv.meta.value();
    }

    if (myArgs.checkCacheStatus) {
        json["isCached"] = drv.isCached;
    }
}

std::string attrPathJoin(std::string_view root, std::string_view attr) {
    std::stringstream s;
    if (!root.empty())
        s << root + ".";
    // Escape token if containing dots
    if (attr.find(".") != std::string::npos)
        s << "\"" + attr + "\"";
    else
        s << attr;
    return s.str();
}

void addGCRoot(EvalState const &state, Drv const &drv) {
    if (myArgs.gcRootsDir != "") {
        Path root = myArgs.gcRootsDir + "/" + baseNameOf(drv.drvPath);
        if (!pathExists(root)) {
            auto localStore = state.store.dynamic_pointer_cast<LocalFSStore>();
            auto storePath = localStore->parseStorePath(drv.drvPath);
            localStore->addPermRoot(storePath, root);
        }
    }
}

template <typename F1, typename F2>
void evaluate(ref<EvalState> state, Bindings &autoArgs, Value *vRoot,
              std::string const &attrPath, F1 f1, F2 f2) {

    debug("Evaluating attrPath %s", attrPath);

    auto vTmp = findAlongAttrPath(*state, attrPath, autoArgs, *vRoot).first;
    auto v = state->allocValue();
    state->autoCallFunction(autoArgs, *vTmp, *v);

    if (v->type() == nAttrs) {
        if (auto drvInfo = getDerivation(*state, *v, false)) {
            auto drv = mkDrv(*state, *drvInfo);

            /* Register the derivation as a GC root.  !!! This
               registers roots for jobs that we may have already
               done. */
            addGCRoot(*state, drv);
            f1(drv);
        } else {
            bool hasRecurseForDerivations = [&]() {
                auto attrv = v->attrs->get(state->sRecurseForDerivations);
                return attrv && state->forceBool(
                                    *attrv->value, attrv->pos,
                                    "while evaluating recurseForDerivations");
            }();

            // We do not require `recurseForDerivations = true;` for
            // top-level attrset
            if (attrPath == "" || myArgs.forceRecurse ||
                hasRecurseForDerivations) {
                auto attrs = std::vector<std::string>();
                attrs.reserve(v->attrs->size());
                for (auto &i : *v->attrs) {
                    const std::string &name = state->symbols[i.name];
                    attrs.push_back(attrPathJoin(attrPath, name));
                }
                f2(attrs);
            }
        }
    }
}

int main(int argc, char **argv) {
    /* Prevent undeclared dependencies in the evaluation via
       $NIX_PATH. */
    unsetenv("NIX_PATH");

    /* We are doing the garbage collection by killing forks */
    setenv("GC_DONT_GC", "1", 1);

    return handleExceptions(argv[0], [&]() {
        initNix();
        initGC();

        myArgs.parseCmdline(argvToStrings(argc, argv));

        /* FIXME: The build hook in conjunction with import-from-derivation is
         * causing "unexpected EOF" during eval */
        settings.builders = "";

        /* Prevent access to paths outside of the Nix search path and
           to the environment. */
        evalSettings.restrictEval = false;

        /* When building a flake, use pure evaluation (no access to
           'getEnv', 'currentSystem' etc. */
        if (myArgs.impure) {
            evalSettings.pureEval = false;
        } else if (myArgs.flake) {
            evalSettings.pureEval = true;
        }

        if (myArgs.expr == "")
            throw UsageError("no expression specified");

        if (myArgs.gcRootsDir == "") {
            printMsg(lvlError, "warning: `--gc-roots-dir' not specified");
        } else {
            myArgs.gcRootsDir = std::filesystem::absolute(myArgs.gcRootsDir);
        }

        if (myArgs.showTrace) {
            loggerSettings.showTrace.assign(true);
        }

        // I don't think this needs to be shared, we own it and it could be
        // on the stack. But InstallableFlake wants a ref<EvalState> which
        // is a shared pointer, so I wonder what it does with it. Better
        // play safe and give it what it wants.
        auto state = make_ref<EvalState>(myArgs.searchPath,
                                         openStore(*myArgs.evalStoreUrl));

        Bindings &autoArgs = *myArgs.getAutoArgs(*state);

        // lazily initialised per-thread at first use (I think this is
        // expensive)
        Value *vRoot = topLevelValue(state, autoArgs);

        std::queue<std::string> q;
        q.push("");

        std::jthread([&]() {
            while (q.size() > 0) {
                auto attrPath = q.front();
                q.pop();

                evaluate(
                    state, autoArgs, vRoot, attrPath,
                    [&](Drv const &drv) {
                        std::cout << nlohmann::json{drv} << std::endl;
                    },
                    [&](auto &&attrs) {
                        for (auto &&attr : attrs)
                            q.push(attr);
                    });
            };
        });
    });
}
