//
// Created by Krzysztof Tulidowicz on 07.01.2020.
//

//
// Created by Krzysztof Tulidowicz on 07.01.2020.
//

#ifndef BSC_COMMANDLINEPARAMETERS_H
#define BSC_COMMANDLINEPARAMETERS_H

#include <argp.h>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
//
// Created by Krzysztof Tulidowicz on 08.01.2020.
//

#ifndef BSC_FROMSTRING_H
#define BSC_FROMSTRING_H

#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace bsc {

    //@todo C++20 all of those SFINAE enable_if can be replaced by concepts, but concepts do not quite work yet in
    //current
    // compilers. try again when GCC 11 comes out.
    template<typename T>
    struct IsPairT : std::false_type {};

    template<typename T, typename U>
    struct IsPairT<std::pair<T, U>> : std::true_type {};

    //    template<typename T>
    //    constexpr bool is_pair_v = is_pair<T>::value;
    template<typename T>
    concept IsPair = IsPairT<T>::value;

    template<typename T, typename _ = void>
    struct IsContainerNotStringCheck : std::false_type {};

    template<typename T>
    struct IsContainerNotStringCheck<T,
                                   std::void_t<typename T::value_type,
                                               typename T::size_type,
                                               typename T::allocator_type,
                                               typename T::iterator,
                                               typename T::const_iterator,
                                               decltype(std::declval<T>().size()),
                                               decltype(std::declval<T>().begin()),
                                               decltype(std::declval<T>().end()),
                                               decltype(std::declval<T>().cbegin()),
                                               decltype(std::declval<T>().cend()),
                                               std::enable_if_t<!std::is_convertible_v<T, std::string>>

                                               >> : public std::true_type {};
    template<typename T>
    concept IsContainerNotString = IsContainerNotStringCheck<T>::value;
    /*std::negation_v<std::is_convertible<T, std::string>> && requires {
            typename T::value_type;
                    typename T::size_type;
                    typename T::allocator_type;
                    typename T::iterator;
                    typename T::const_iterator;
                    std::declval<T>().size();
                    std::declval<T>().begin();
                    std::declval<T>().end();
                    std::declval<T>().cbegin();
                    std::declval<T>().cend();
        };*/

    class StringParseException : public std::invalid_argument {
    public:
        explicit StringParseException(const std::string& arg) : invalid_argument(arg) {}
    };

    class Parser {
    public:
        struct ParserConfiguration {
            char csvDelimiter  = ',';
            char pairDelimiter = '=';
        };

    private:
        ParserConfiguration parserConfiguration;

    public:
        explicit Parser(const ParserConfiguration& parserConfiguration) : parserConfiguration(parserConfiguration) {}
        Parser() = default;

    public:
        template<typename ParameterType>
        [[nodiscard]] std::remove_reference_t<ParameterType>
        fromString(const std::string& value,
                   std::enable_if_t<std::numeric_limits<ParameterType>::is_integer, int> = 0) const  {
            try {
                return std::stol(value);
            } catch (std::invalid_argument& e) {
                throw StringParseException("Long parsing failed for value: " + value);
            }
        }

        template<typename ParameterType>
        [[nodiscard]] std::remove_reference_t<ParameterType>
        fromString(const std::string& value, std::enable_if_t<std::is_floating_point_v<ParameterType>, int> = 0) const {
            try {
                return std::stod(value);
            } catch (std::invalid_argument& e) {
                throw StringParseException("Floating parsing failed for value: " + value);
            }
        }

        template<typename ParameterType>
        [[nodiscard]] std::remove_reference_t<ParameterType>
        fromString(const std::string& value,
                   std::enable_if_t<std::is_convertible_v<ParameterType, std::string>, int> = 0) const {
            if (!value.empty()) {
                return ParameterType(value);
            } else {
                throw StringParseException("Can't parse null parameter value");
            }
        }

        template<typename ParameterType>
        [[nodiscard]] std::remove_reference_t<ParameterType> fromString(const std::string& value,
                                                          int = 0) const requires IsPair<ParameterType> {
            try {

                std::stringstream inputStream(value);
                std::string first, second;
                getline(inputStream, first, parserConfiguration.pairDelimiter);
                getline(inputStream, second);
                auto key       = fromString<std::decay_t<typename ParameterType::first_type>>(first.c_str());
                auto pairValue = fromString<typename ParameterType::second_type>(second.c_str());
                return std::make_pair(key, pairValue);
            } catch (std::invalid_argument& e) {
                throw StringParseException("Pair parsing failed for value: " + value);
            }
        }

        template<typename ParameterType>
        [[nodiscard]] std::remove_reference_t<ParameterType>
        fromString(const std::string& value, std::enable_if_t<IsContainerNotStringCheck<ParameterType>::value, int> = 0) const {
            ParameterType container;
            std::stringstream inputStream(value);
            std::string element;

            while (getline(inputStream, element, parserConfiguration.csvDelimiter)) {
                container.insert(container.end(), fromString<typename ParameterType::value_type>(element.c_str()));
            }

            return container;
        }
    };

    template<>
    [[nodiscard]] inline bool Parser::fromString<bool>(const std::string& value, int)const {
        return true;
    }

    template<>
    [[nodiscard]] inline int Parser::fromString<int>(const std::string& value, int) const{
        try {
            return std::stoi(value);
        } catch (std::invalid_argument& e) {
            throw StringParseException("Integer parsing failed for value: " + value);
        }
    }

    template<>
    [[nodiscard]] inline long Parser::fromString<long>(const std::string& value, int)const {
        try {
            return std::stol(value);
        } catch (std::invalid_argument& e) {
            throw StringParseException("Long parsing failed for value: " + value);
        }
    }

    template<>
    [[nodiscard]] inline unsigned long Parser::fromString<unsigned long>(const std::string& value, int)const {
        try {
            return std::stoul(value);
        } catch (std::invalid_argument& e) {
            throw StringParseException("Unsigned long parsing failed for value: " + value);
        }
    }

    template<>
    [[nodiscard]] inline float Parser::fromString<float>(const std::string& value, int) const{
        try {
            return std::stof(value);
        } catch (std::invalid_argument& e) {
            throw StringParseException("Floating parsing failed for value: " + value);
        }
    }

    template<>
    [[nodiscard]] inline double Parser::fromString<double>(const std::string& value, int) const{
        try {
            return std::stod(value);
        } catch (std::invalid_argument& e) {
            throw StringParseException("Floating parsing failed for value: " + value);
        }
    }

    template<>
    [[nodiscard]] inline long double Parser::fromString<long double>(const std::string& value, int) const {
        try {
            return std::stold(value);
        } catch (std::invalid_argument& e) {
            throw StringParseException("Floating parsing failed for value: " + value);
        }
    }

    template<typename ParameterType>
    [[nodiscard]] auto fromString(const std::string& value) {
        static Parser parser;
        return parser.fromString<ParameterType>(value);
    }

}// namespace bsc

#endif// BSC_FROMSTRING_H

#include <set>
#include <span>
#include <utility>

namespace bsc {

    enum class ParseConfiguration {
        simple,
        silent,
    };

    class CommandLineParameters;

    template<typename T>
    concept ParametersClass = std::is_base_of_v<CommandLineParameters, T>;

    class ValueNotAllowed : public std::domain_error {
    public:
        const std::set<std::string> allowedValues;

        ValueNotAllowed(const std::string& arg);
        ValueNotAllowed(const std::string& arg, std::remove_cvref_t<decltype(allowedValues)> a);
        ValueNotAllowed(const ValueNotAllowed&) = default;
        ValueNotAllowed(ValueNotAllowed&&)      = default;
    };

    class CommandLineParameters {
    private:
        class ParserBuilder;

        class ArgumentParser {
        public:
            using OptionParseFunc   = std::function<void(const char*, Parser&)>;
            using ArgumentParseFunc = std::function<void(const std::string&, Parser&)>;

        private:
            std::vector<argp_option> argpOptions{};
            std::string doc{};
            std::string argDoc{};
            argp argParams{};
            ParseConfiguration parseConfiguration;
            unsigned flags{};
            std::map<decltype(argp_option::key), OptionParseFunc> parseMap{};
            std::vector<std::string> rawArguments{};
            std::string commandName;
            struct ArgumentDescriptor {
                ArgumentParseFunc argumentParseFunc{};
                decltype(rawArguments)::size_type argumentIndex{};
                std::optional<std::string> argumentName{};
            };
            std::vector<ArgumentDescriptor> argumentDescriptors{};
            std::vector<std::string> usageDocs    = {};
            std::optional<std::string> beforeInfo = std::nullopt;
            std::optional<std::string> afterInfo  = std::nullopt;
            std::optional<decltype(rawArguments)::size_type> requiredArgumentsCount;
            Parser parser{};

            void incrementRequiredArguments() {
                if (!requiredArgumentsCount.has_value()) {
                    requiredArgumentsCount = 0;
                }
                ++*requiredArgumentsCount;
            }
            void parseNamedArguments();

        public:
            static error_t parseArgument(int key, char* arg, struct argp_state* state);

            void prepareParser(ParseConfiguration configuration, const Parser&);
            void parse(int argc, char* argv[]);
            static char* helpFilter(int key, const char* text, void* input);
            auto& getParsedArguments() { return rawArguments; }
            auto getRemainingArguments() {
                return std::span<std::string>(rawArguments.begin() +
                                                      (requiredArgumentsCount ? *requiredArgumentsCount : 0),
                                              rawArguments.end());
            };
            auto& getCommandName() {
                return commandName;
            }

            friend class CommandLineParameters::ParserBuilder;
            friend class CommandLineParser;
            void prepareArgumentUsage();
        };

        class ParserBuilder {
        private:
            std::shared_ptr<ArgumentParser> parser = nullptr;
            int currentKey                         = 0;

        public:
            struct ParserOptions {
                std::optional<char> shortKey{};
                std::optional<std::string_view> longKey{};
                std::optional<std::string_view> argumentName{};
                int flags{};
                std::optional<std::string_view> doc{};
            };
            void addOption(ParserOptions parserOptions, ArgumentParser::OptionParseFunc parserFunction);

            void addGroup(const char* doc);
            void addAlias(char shortKey, const char* longKey = nullptr);
            void addAlias(const char* longKey);
            void addUsage(std::string usage);

            void addDoc(std::string doc);
            void addArgument(ArgumentParser::ArgumentParseFunc parserFunction,
                             std::optional<std::string> argumentName = std::nullopt);

            std::shared_ptr<ArgumentParser> make();

            void reset();
        };

        static ParserBuilder& parserBuilder() {
            static thread_local ParserBuilder parserBuilder;
            return parserBuilder;
        }

        const std::shared_ptr<ArgumentParser> parser;

        template<typename T>
        friend class BaseParameter;

        template<typename T>
        friend class Parameter;

        template<typename T>
        friend class OptionalParameter;

        template<typename T>
        friend class RequiredParameter;

        friend class Group;
        template<typename T>
        friend class Argument;
        friend class Usage;

        friend class Doc;

        friend class Alias;

    public:
        CommandLineParameters();

        friend class CommandLineParser;

        [[nodiscard]] const std::vector<std::string>& arguments() const { return parser->getParsedArguments(); }
        [[nodiscard]] const std::span<std::string> remainingArguments() const {
            return parser->getRemainingArguments();
        }

        const std::string& commandName() const {
            return parser->getCommandName();
        }
    };

    class CommandLineParser {
    private:
        ParseConfiguration parseConfiguration = ParseConfiguration::simple;
        const Parser parser{};

    public:
        CommandLineParser(ParseConfiguration parseConfiguration, const Parser& parser)
            : parseConfiguration(parseConfiguration), parser(parser) {}
        CommandLineParser() = default;

        template<ParametersClass T>
        [[nodiscard]] T parse(int argc, char* argv[]) {
            static Parser parser;
            T t;
            t.parser->prepareParser(parseConfiguration, parser);
            t.parser->parse(argc, argv);
            return t;
        }

        template<ParametersClass T>
        [[nodiscard]] T parse(const std::vector<std::string>& vals) {
            // guarantee contiguous, null terminated strings
            std::vector<std::vector<char>> vstrings;
            // pointers to those strings
            std::vector<char*> cstrings;
            vstrings.reserve(vals.size() + 1);
            cstrings.reserve(vals.size() + 1);

            for (const auto& val : vals) {
                vstrings.emplace_back(val.begin(), val.end());
                vstrings.back().push_back('\0');
                cstrings.push_back(vstrings.back().data());
            }
            return this->parse<T>(cstrings.size(), cstrings.data());
        }

        template<ParametersClass T>
        [[nodiscard]] T parse(const std::string& commandName, std::vector<std::string> vals) {
            vals.insert(vals.begin(), commandName);
            return this->parse<T>(vals);
        }

        template<ParametersClass T>
        [[nodiscard]] static T defaultParse(int argc, char* argv[]) {
            static CommandLineParser commandLineParser;
            return commandLineParser.parse<T>(argc, argv);
        }

        template<ParametersClass T>
        [[nodiscard]] static T defaultParse(const std::vector<std::string>& vals) {
            static CommandLineParser commandLineParser;
            return commandLineParser.parse<T>(vals);
        }

        template<ParametersClass T>
        [[nodiscard]] static T defaultParse(const std::string& commandName, std::vector<std::string> vals) {
            static CommandLineParser commandLineParser;
            return commandLineParser.parse<T>(commandName, vals);
        }
    };

    template<typename T>
    class BaseParameter {
    public:
        class AllowedValues {
        public:
            using AllowedValuesSet = std::set<std::string>;
            using GetterFunc       = std::function<AllowedValuesSet(void)>;

        private:
            GetterFunc getter = []() { return AllowedValuesSet{}; };

        public:
            AllowedValues(std::initializer_list<AllowedValuesSet ::value_type> list) {
                std::set<T> set = list;
                getter          = [set]() { return set; };
            }
            AllowedValues(AllowedValuesSet set) {
                getter = [set]() { return set; };
            }
            template<typename Func>
            AllowedValues(Func func) requires std::is_invocable_r_v<AllowedValuesSet, Func> {
                getter = func;
            }

            AllowedValues()                     = default;
            AllowedValues(const AllowedValues&) = default;
            AllowedValues(AllowedValues&&)      = default;
            AllowedValuesSet get() { return getter(); }
        };

    protected:
        std::optional<T> value;

    private:
        int counter = 0;
        AllowedValues allowedValues{};

        CommandLineParameters::ArgumentParser::OptionParseFunc makeParseFunction() {
            return [this](const char* input, Parser& parser) {
                std::string text = input != nullptr ? input : "";
                //@todo maybe this should be optimized so it is only called once
                const auto& validValues = this->allowedValues.get();
                //@todo case sensitive or not
                if (!validValues.empty() && !validValues.contains(text)) {
                    using namespace std::string_literals;
                    throw ValueNotAllowed("Value "s + text + " is not allowed.", validValues);
                }
                if (!value) {
                    value = parser.fromString<T>(text);
                } else {
                    // if parameter is mentioned multiple times and it's a container, combine options. otherwise,
                    // overwrite.
                    if constexpr (IsContainerNotString<T>) {
                        auto tempValue = parser.fromString<T>(text);
                        std::for_each(tempValue.begin(), tempValue.end(), [this](auto& i) {
                            value->insert(value->end(), i);
                        });
                    } else {
                        value = parser.fromString<T>(text);
                    }
                }

                counter++;
            };
        }

        int makeFlags(bool optional, bool hidden) {
            int flags = 0;
            if (optional) flags |= OPTION_ARG_OPTIONAL;
            if (hidden) flags |= OPTION_HIDDEN;
            return flags;
        }

    protected:
        void setValue(const T& v) { value = v; }

    public:
        //@todo maybe I should add callback here that will be called after this value is set?
        struct BaseParameterDefinition {
            std::optional<char> shortKey{};
            std::optional<std::string_view> longKey{};
            std::optional<std::string_view> argumentName{};
            std::optional<std::string_view> doc{};
            bool optional = false;
            bool hidden   = false;
            std::optional<T> defaultValue{};
            AllowedValues allowedValues{};
        };

        BaseParameter(BaseParameterDefinition def) : allowedValues(def.allowedValues) {
            value         = def.defaultValue;
            auto& builder = bsc::CommandLineParameters::parserBuilder();
            builder.addOption({.shortKey     = def.shortKey,
                               .longKey      = def.longKey,
                               .argumentName = def.argumentName,
                               .flags        = makeFlags(def.optional, def.hidden),
                               .doc          = def.doc},
                              makeParseFunction());
        }

        const decltype(value)& operator()() const { return value; }

        [[nodiscard]] auto count() const { return counter; }
    };

    template<typename T>
    class Parameter : public BaseParameter<T> {

    public:
        using AllowedValues = typename BaseParameter<T>::AllowedValues;
        struct ParameterDefinition {
            std::optional<char> shortKey{};
            std::optional<std::string_view> longKey{};
            std::optional<std::string_view> argumentName{};
            std::optional<std::string_view> doc{};
            std::optional<T> defaultValue{};
            AllowedValues allowedValues{};
        };

        Parameter(ParameterDefinition def)// NOLINT
            : BaseParameter<T>({.shortKey      = def.shortKey,
                                .longKey       = def.longKey,
                                .argumentName  = def.argumentName,
                                .doc           = def.doc,
                                .defaultValue  = def.defaultValue,
                                .allowedValues = def.allowedValues}) {}
    };

    template<typename T>
    class DefaultParameter : public BaseParameter<T> {

    public:
        using AllowedValues = typename BaseParameter<T>::AllowedValues;
        struct DefaultParameterDefinition {
            std::optional<char> shortKey{};
            std::optional<std::string_view> longKey{};
            std::optional<std::string_view> argumentName{};
            std::optional<std::string_view> doc{};
            T defaultValue{};
            AllowedValues allowedValues{};
        };

        DefaultParameter(DefaultParameterDefinition def)// NOLINT
            : BaseParameter<T>({.shortKey      = def.shortKey,
                                .longKey       = def.longKey,
                                .argumentName  = def.argumentName,
                                .doc           = def.doc,
                                .defaultValue  = std::move(def.defaultValue),
                                .allowedValues = def.allowedValues}) {}

        const auto& operator()() const { return *this->value; }// NOLINT
    };

    template<typename T>
    class OptionalParameter : public BaseParameter<T> {
    public:
        OptionalParameter(char shortKey,
                          const char* longKey,
                          const char* argumentName,
                          const char* doc,
                          const std::optional<T>& defaultValue)
            : BaseParameter<T>(shortKey, longKey, doc, argumentName, defaultValue, true, false) {}

        OptionalParameter(char shortKey, const char* argumentName, const char* doc)
            : BaseParameter<T>(shortKey, argumentName, doc, true, false) {}

        OptionalParameter(const char* longKey, const char* argumentName, const char* doc)
            : BaseParameter<T>(longKey, argumentName, doc, true, false) {}
    };

    template<typename T>
    class HiddenParameter : public OptionalParameter<T> {};

    class Group {

    public:
        Group(const char* doc) {
            auto& builder = CommandLineParameters::parserBuilder();
            builder.addGroup(doc);
        }
    };

    class Alias {
    public:
        Alias(char shortKey) {
            auto& builder = CommandLineParameters::parserBuilder();
            builder.addAlias(shortKey);
        }

        Alias(const char* longKey) {
            auto& builder = CommandLineParameters::parserBuilder();
            builder.addAlias(longKey);
        }

        Alias(char key, const char* longKey) {
            auto& builder = CommandLineParameters::parserBuilder();
            builder.addAlias(key, longKey);
        }
    };

    class Usage {
    public:
        Usage(std::string usage) {
            auto& builder = CommandLineParameters::parserBuilder();
            builder.addUsage(std::move(usage));
        }

        Usage(const std::vector<std::string>& usage) {
            auto& builder = CommandLineParameters::parserBuilder();
            for (const auto& item : usage) {
                builder.addUsage(item);
            }
        }
    };

    class Doc {
    public:
        Doc(std::string doc) {
            auto& builder = CommandLineParameters::parserBuilder();
            builder.addDoc(std::move(doc));
        }
    };

    template<typename T>
    class RequiredParameter : public BaseParameter<T> {
    public:
        RequiredParameter(char shortKey, const char* longKey, const char* argumentName, const char* doc)
            : BaseParameter<T>(shortKey, longKey, argumentName, doc, false, false) {}

        RequiredParameter(char shortKey, const char* argumentName, const char* doc)
            : BaseParameter<T>(shortKey, argumentName, doc, false, false) {}

        RequiredParameter(const char* longKey, const char* argumentName, const char* doc)
            : BaseParameter<T>(longKey, argumentName, doc, false, false) {}
    };

    using Flag = Parameter<bool>;

    /**
     * Named argument from command line
     */
    template<typename T>
    class Argument {
    private:
        std::optional<T> value;
        CommandLineParameters::ArgumentParser::ArgumentParseFunc makeParseFunction() {
            return [this](const std::string& text, Parser& parser) {
                // this if is probably not necessary, it will be a bug to call it more than once.
                if (!value) {
                    value = parser.fromString<T>(text);
                }
            };
        }

    public:
        Argument() {
            auto& builder = CommandLineParameters::parserBuilder();
            builder.addArgument(makeParseFunction());
        }

        Argument(const std::string& name) {
            auto& builder = CommandLineParameters::parserBuilder();
            builder.addArgument(makeParseFunction(), name);
        }

        const auto& operator()() const { return *this->value; }
    };
}// namespace bsc

#endif// BSC_COMMANDLINEPARAMETERS_H

#include <memory>
#include <numeric>
#include <utility>
namespace bsc {
    inline CommandLineParameters::CommandLineParameters() : parser(parserBuilder().make()) {}

    inline std::shared_ptr<CommandLineParameters::ArgumentParser> CommandLineParameters::ParserBuilder::make() {
        reset();
        return parser;
    }

    inline void CommandLineParameters::ParserBuilder::reset() {
        // reset internal state of builder
        parser     = std::make_shared<ArgumentParser>();
        currentKey = 1000;
    }

    inline void CommandLineParameters::ParserBuilder::addOption(
            CommandLineParameters::ParserBuilder::ParserOptions parserOptions,
            CommandLineParameters::ArgumentParser::OptionParseFunc parserFunction) {
        // if there is no argument name provided, then argument will be optional
        int flags = parserOptions.argumentName.has_value() ? parserOptions.flags
                                                           : parserOptions.flags | OPTION_ARG_OPTIONAL;
        auto arg  = argp_option{.name  = parserOptions.longKey ? parserOptions.longKey->data() : nullptr,
                               .key   = parserOptions.shortKey ? *parserOptions.shortKey : ++currentKey,
                               .arg   = parserOptions.argumentName ? parserOptions.argumentName->data() : nullptr,
                               .flags = flags,
                               .doc   = parserOptions.doc ? parserOptions.doc->data() : nullptr,
                               .group = 0};
        parser->argpOptions.push_back(arg);
        parser->parseMap[arg.key] = std::move(parserFunction);
    }

    inline void CommandLineParameters::ParserBuilder::addGroup(const char* doc) {
        auto arg = argp_option{nullptr, 0, nullptr, 0, doc, 0};
        parser->argpOptions.push_back(arg);
    }

    inline void CommandLineParameters::ParserBuilder::addAlias(char shortKey, const char* longKey) {
        auto arg = argp_option{longKey, shortKey, nullptr, OPTION_ALIAS, nullptr, 0};
        parser->argpOptions.push_back(arg);
    }

    inline void CommandLineParameters::ParserBuilder::addAlias(const char* longKey) {
        auto arg = argp_option{longKey, ++currentKey, nullptr, OPTION_ALIAS, nullptr, 0};
        parser->argpOptions.push_back(arg);
    }

    inline void CommandLineParameters::ParserBuilder::addDoc(std::string doc) {
        if (parser->argpOptions.empty()) {
            auto& before = parser->beforeInfo;
            if (before.has_value()) {
                *before += "\n" + doc;
            } else {
                before = doc;
            }
        } else {
            auto& after = parser->afterInfo;
            if (after.has_value()) {
                *after += "\n" + doc;
            } else {
                after = doc;
            }
        }
    }

    inline void CommandLineParameters::ParserBuilder::addUsage(std::string usage) {
        parser->usageDocs.push_back(std::move(usage));
    }
    inline void CommandLineParameters::ParserBuilder::addArgument(ArgumentParser::ArgumentParseFunc parserFunction,
                                                           std::optional<std::string> argumentName) {
        parser->argumentDescriptors.push_back({.argumentParseFunc = std::move(parserFunction),
                                               .argumentIndex     = parser->argumentDescriptors.size(),
                                               .argumentName      = std::move(argumentName)});
        parser->incrementRequiredArguments();
    }

    inline error_t CommandLineParameters::ArgumentParser::parseArgument(int key, char* arg, struct argp_state* state) {
        auto* self = static_cast<ArgumentParser*>(state->input);
        switch (key) {
            case ARGP_KEY_INIT:
                break;

            case ARGP_KEY_ARG:
                self->rawArguments.emplace_back(arg);
                {
                    auto next   = state->next;
                    state->next = state->argc;
                    while (next < state->argc && state->argv[next]) {
                        self->rawArguments.emplace_back(state->argv[next]);
                        next++;
                    }
                }
                break;

            case ARGP_KEY_END:
                if (self->requiredArgumentsCount.has_value()) {
                    if (self->requiredArgumentsCount.value() > self->rawArguments.size()) {
                        argp_error(state,
                                   "Arguments required: %zu, got %zu",
                                   *self->requiredArgumentsCount,
                                   self->rawArguments.size());
                    }
                }
                break;

            case ARGP_KEY_NO_ARGS:

                break;
            case ARGP_KEY_SUCCESS:

                break;

            case ARGP_KEY_FINI:
                break;
            case ARGP_KEY_ERROR:
                break;

            default:
                if (self->parseMap.contains(key)) {
                    try {
                        self->parseMap[key](arg, self->parser);
                    } catch (StringParseException& e) {
                        if (self->parseConfiguration == ParseConfiguration::simple) {
                            argp_error(state,
                                       "Argument \"%s\" parse failed for '%c' with error: [%s]",
                                       arg,
                                       key,
                                       e.what());
                        } else {
                            throw e;
                        }
                    } catch (ValueNotAllowed& e) {
                        if (self->parseConfiguration == ParseConfiguration::simple) {
                            using namespace std::string_literals;
                            std::string allowedValues = std::accumulate(
                                    e.allowedValues.begin(),
                                    e.allowedValues.end(),
                                    ""s,
                                    [](const auto& a, const auto& b) { return a.empty() ? b : a + ", " + b; });
                            auto failedOption = std::find_if(self->argpOptions.begin(),
                                                             self->argpOptions.end(),
                                                             [&key](argp_option& option) { return option.key == key; });
                            std::string parameterName =
                                    (failedOption != self->argpOptions.end() && failedOption->name != nullptr)
                                            ? failedOption->name
                                    : key < 128 ? std::string(1, key)
                                                : "unknown";
                            argp_error(state,
                                       "Parameter [%s] : Value \"%s\" is not allowed. Allowed values: %s",
                                       parameterName.c_str(),
                                       arg,
                                       allowedValues.c_str());
                        } else {
                            throw e;
                        }
                    }

                } else {
                    return ARGP_ERR_UNKNOWN;
                }
                break;
        }

        return 0;
    }

    inline void CommandLineParameters::ArgumentParser::parse(int argc, char** argv) {
        if (argc >0 && argv[0] != nullptr) {
            commandName = argv[0];
        }
        argp_parse(&argParams, argc, argv, flags, nullptr, this);
        parseNamedArguments();
    }

    inline void CommandLineParameters::ArgumentParser::prepareParser(ParseConfiguration configuration,
                                                              const Parser& newParser) {
        using namespace std::string_literals;
        this->parseConfiguration = configuration;
        this->parser             = newParser;
        // close argOptions:
        argpOptions.push_back({nullptr, 0, nullptr, 0, nullptr, 0});
        if (beforeInfo || afterInfo) {
            doc = beforeInfo.value_or(" ") + "\v" + afterInfo.value_or("");
        }

        prepareArgumentUsage();

        argDoc = std::accumulate(usageDocs.begin(), usageDocs.end(), ""s, [](const auto& a, const auto& b) {
            if (a.empty()) {
                return b;
            } else {
                return a + "\n" + b;
            }
        });
        flags  = ARGP_IN_ORDER;
        switch (configuration) {
            case ParseConfiguration::simple:
                break;

            case ParseConfiguration::silent:
                flags |= ARGP_SILENT;
                break;
        }

        argParams = {argpOptions.data(),
                     ArgumentParser::parseArgument,
                     argDoc.c_str(),
                     doc.c_str(),
                     nullptr,
                     nullptr,
                     nullptr};
    }

    inline char* CommandLineParameters::ArgumentParser::helpFilter(int key, const char* text, void* input) {
        if (text != nullptr) {
            using namespace std::string_literals;
            //        LOGGER("TEXT FILTER IS : "s + text);
        } else {
            //        LOGGER("TEXT IS NULL");
        }
        return nullptr;
    }
    inline void CommandLineParameters::ArgumentParser::parseNamedArguments() {
        for (const auto& descriptor : argumentDescriptors) {
            if (descriptor.argumentIndex < rawArguments.size()) {
                descriptor.argumentParseFunc(rawArguments[descriptor.argumentIndex], this->parser);
            }
        }
    }
    inline void CommandLineParameters::ArgumentParser::prepareArgumentUsage() {
        static const std::string defaultArgumentName = "ARG#";
        std::string usageString{};
        for (const auto& descriptor : argumentDescriptors) {
            if (descriptor.argumentName.has_value()) {
                usageString += *descriptor.argumentName;
            } else {
                usageString += defaultArgumentName + std::to_string(descriptor.argumentIndex + 1);
            }
            usageString += " ";
        }
        if (usageString.size() > 1) usageString.pop_back();
        usageDocs.insert(usageDocs.begin(), usageString);
    }

    inline ValueNotAllowed::ValueNotAllowed(const std::string& arg) : ValueNotAllowed(arg, {}) {}
    inline ValueNotAllowed::ValueNotAllowed(const std::string& arg, std::remove_cvref_t<decltype(allowedValues)> a)
        : domain_error(arg), allowedValues(std::move(a)) {}
}// namespace bsc