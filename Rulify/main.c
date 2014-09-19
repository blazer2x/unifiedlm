//compile with flag -Wno-char-subscripts

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>


//Rules ripped from hashcat/ppro/jtr
#define RULE_OP_MANGLE_NOOP             ':' // does nothing
#define RULE_OP_MANGLE_LREST            'l' // lower case all chars
#define RULE_OP_MANGLE_UREST            'u' // upper case all chars
#define RULE_OP_MANGLE_LREST_UFIRST     'c' // lower case all chars, upper case 1st
#define RULE_OP_MANGLE_UREST_LFIRST     'C' // upper case all chars, lower case 1st
#define RULE_OP_MANGLE_TREST            't' // switch the case of each char
#define RULE_OP_MANGLE_TOGGLE_AT        'T' // switch the case of each char on pos N
#define RULE_OP_MANGLE_REVERSE          'r' // reverse word
#define RULE_OP_MANGLE_DUPEWORD         'd' // append word to itself
#define RULE_OP_MANGLE_DUPEWORD_TIMES   'p' // append word to itself N times
#define RULE_OP_MANGLE_REFLECT          'f' // reflect word (append reversed word)
#define RULE_OP_MANGLE_ROTATE_LEFT      '{' // rotate the word left.  ex: hello -> elloh
#define RULE_OP_MANGLE_ROTATE_RIGHT     '}' // rotate the word right. ex: hello -> ohell
#define RULE_OP_MANGLE_APPEND           '$' // append char X
#define RULE_OP_MANGLE_PREPEND          '^' // prepend char X
#define RULE_OP_MANGLE_DELETE_FIRST     '[' // delete first char of word
#define RULE_OP_MANGLE_DELETE_LAST      ']' // delete last char of word
#define RULE_OP_MANGLE_DELETE_AT        'D' // delete char of word at pos N
#define RULE_OP_MANGLE_EXTRACT          'x' // delete X chars of word at pos N
#define RULE_OP_MANGLE_INSERT           'i' // insert char X at pos N
#define RULE_OP_MANGLE_OVERSTRIKE       'o' // overwrite with char X at pos N
#define RULE_OP_MANGLE_TRUNCATE_AT      '\''// cut the word at pos N
#define RULE_OP_MANGLE_REPLACE          's' // replace all chars X with char Y
#define RULE_OP_MANGLE_PURGECHAR        '@' // purge all instances of char X
#define RULE_OP_MANGLE_DUPECHAR_FIRST   'z' // prepend first char of word to itself. ex: hello -> hhello
#define RULE_OP_MANGLE_DUPECHAR_LAST    'Z' // append last char of word to itself.   ex: hello -> helloo
#define RULE_OP_MANGLE_DUPECHAR_ALL     'q' // duplicate all chars. ex: hello -> hheelllloo
#define RULE_OP_MANGLE_EXTRACT_MEMORY   'X' // insert substring delimited by N and M into current word at position I
#define RULE_OP_MANGLE_APPEND_MEMORY    '4' // insert the word saved by 'M' at the end of current word
#define RULE_OP_MANGLE_PREPEND_MEMORY   '6' // insert the word saved by 'M' at the beginning of current word
#define RULE_OP_MEMORIZE                'M' // memorize the current word
//End standard rules

//Additional rules not found in ppro/hm/hashcat/jtr
#define RULE_OP_REPLACE_SINGLE_LEFT     'S' // replace a single instance of X with Y from the left SXY
#define RULE_OP_REPLACE_SINGLE_RIGHT    'R' // replace a single instance of X with Y from the right RXY
#define RULE_OP_REPLACE_SINGLE_POS      'F' // Find the Z instance of X and replace with Y FZXY
#define RULE_OP_REPLACE_SINGLE_POS_DUAL 'J' // Find the Z instance of X and replace with YQ JZXYQ
#define RULE_OP_TOGGLE_LEFT             'h' // Toggle the case of the X letter from the left (not implemented)
#define RULE_OP_TOGGLE_RIGHT            'H' // Toggle the case of the X letter from the right (not implemented)
//End additional rules

//Extra memory functions
#define RULE_MEM_TOGGLE                 '0' // Toggle memory mode (rules will be applied to memory, make sure it is untoggled)
#define RULE_MEM_CUT_BLOCK              'v' // move a block from pos X to Y into memory
#define RULE_MEM_COPY_BLOCK             'm' // copy a block from pos X to Y into memory (can use X mode instead)
#define RULE_MEM_INSERT                 'I' // Inserts memory into line at pos X (can use X mode instead)
#define RULE_MEM_OVERWRITE              'O' // Overwrites line with memory at pos X
//End extra memory functions

//Extra Rules from hashcat
#define RULE_OP_SWAPFRONT               'k' //Swap first two characters
#define RULE_OP_SWAPBACK                'K' //Swap last two characters
#define RULE_OP_SWAPCHARS               '*' //Swaps character X with Y
#define RULE_OP_CLONEFORWARD            '.' //Replaces character @ N with value @ N plus 1
#define RULE_OP_CLONEBACKWARD           ',' //Replaces character @ N with value @ N minus 1
#define RULE_OP_ASCIIUP                 '+' //Increment character @ N by 1 ascii value
#define RULE_OP_ASCIIDOWN               '-' //Decrement character @ N by 1 ascii value
#define RULE_OP_CLONEBLOCKF             'y' //Duplicates first N characters
#define RULE_OP_CLONEBLOCKR             'Y' //Duplicates last N characters
#define RULE_OP_TITLE                   'E' //Lower case the whole line, then upper case the first letter and every letter after a space
//End Extra Rules

//Additional gating rules (use with |)
#define RULE_GATE                       '|' //Use this with the below numbers
#define RULE_GATE_LENGTH_EQUAL          '2' //Only process rule if length is less than x '|27' (equal to len 7)
#define RULE_GATE_STARTING_CSET         '5' //Only process rule if Number of Starting Chars X is Charset Y '|53l' (First 3 chars is lowercase) [luds]
#define RULE_GATE_ENDING_CSET           '6' //Only process rule if Number of Ending Chars X is Charset Y '|64s' (Last 4 chars is symbols) [luds]
//End gating rules

#define Rule_WHILE_ENDING_CSET          '3' //Processes the next rule while ending cset matching (not implemented)
#define Rule_WHILE_STARTING_CSET        '4' //Process the next rule while starting cset matching (not implemented)
#define Rule_IF_ENDING_CSET             '7' //Processes the next rule while ending cset matching (not implemented)
#define Rule_IF_STARTING_CSET           '8' //Process the next rule while starting cset matching (not implemented)
#define RULE_IF                         '~' //Simple IF
#define RULE_ELSE                       '`' //Simple ELSE (used with IF)
#define RULE_WHILE                      '_' //While Loop (not implemented)
#define RULE_RANDOM                     '?' //While Loop (not implemented)

//Hashcat Rejection rules (can be used with logic IF)
#define RULE_GATE_LESS                  '<' //Reject plains of length greater than N
#define RULE_GATE_GREATER               '>' //Reject plains of length less than N
#define RULE_GATE_CONTAIN               '!' //Reject plains which contain char X
#define RULE_GATE_NOT_CONTAIN           '/' //Reject plains which do not contain char X
#define RULE_GATE_FIRSTCHAR             '(' //Start with char (X
#define RULE_GATE_LASTCHAR              ')' //Ends with char )X
#define RULE_GATE_EQUALSCHAR_AT         '=' //Reject plains which do not have char X at position N
#define RULE_GATE_MEM_CONTAINS          'Q' //Reject plains where the memory saved matches current word
//End hashcat rejection rules

char mapstring[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; //Used to map the chars to positions
char singleR[] = ":lucCtrdf[]{}qM46Q~E0\""; //Rules with single char
char DoubleR[] = "Tp$^DzZ@\\<>!/()IO"; //Rules with double char
char TripleR[] = "ios=mvSR"; //Rules with three chars
char QuadR[] = "XF"; //Rules with quadruple char
int RuleJump[100];
int LongJump = 0;
//Logical operators
char logicOPs[] = "<>!/()=Q";
int isLogical[127] = {0};
int RuleOPs[127] = {0};
char toggleMap[BUFSIZ];
int charMap[256]; //Holds the ASCII rep of luds for those sets
//Used to generate the correct positional maps to map the chars into positions

int posMap[127];
//Self explanatory
char numbers[] = "0123456789";
char symbols[] = "!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/ ]";
char lower[] = "abcdefghijklmnopqrstuvwxyz";
char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char all[] = "!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/ ]0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

char uspecial[] = "ÀÁÂÄÃÅÆÇÐÈÉÊËÌÍÎÏÑÒÓÔÖÕØŒŠÙÛÚÜÝŸŽÞ";
char lspecial[] = "àáâäãåæçÐèéêëìíîïñòóôöõøœšùûúüýÿžþ";


int randomize(int min, int max){
   return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}


int remSpace(char * buffer, int pos)
{
    if (buffer[pos+1] == 32)
    {
        strcpy(buffer+pos+1,buffer+pos+2);
        return 1;
    }
    return 0;
}
//Routine which gets the pointer to the read rule
int validateRule(char * rule_buff)
{


    int rule_len = strlen(rule_buff);  //Holds the length (chars) of the rule
    int u = 0; //Variable we use to process loops

    int skip = 0; //Denotes whether a skip is needing as some rules contain more than 1 character (2,3,4)
    int validMap[BUFSIZ]; //Holds the mapping of position to RulePos
    int mem_mode = 0;
    int rand_mode = 0;
    //Initialize the map (position to > RulePos [0-Z]) to zero
    for (u = 0; u< BUFSIZ; u++)
    {
        validMap[u] = 0;
    }

    //Flag the positions which we know will be valid to one [0-Z] 62 positions
    for (u = 0; u< sizeof(mapstring); u++)
    {
        validMap[(int)mapstring[u]] = 1;
    }

    //Start looping through the characters in the rule and process
    for (u = 0; u<rule_len; u++)
    {
        if (skip !=0 )
        {
            skip--; //If a skip is issues, simply decrease the skip counter and do not process (this is needed since some rules contain more than a single char)
            continue;
        }
        if (rule_buff[u] == ' ') //The rule processor ignores space characters (treats them as blank so just skip them)
        {
            strcpy(rule_buff+u,rule_buff+u+1);
            rule_len--;
            u--;
            continue;
        }

        if (rule_buff[u] == 34) //The rule processor ignores space characters (treats them as blank so just skip them)
        {
            continue;
        }
        if (rule_buff[u] == '`') //The rule processor ignores space characters (treats them as blank so just skip them)
        {
            continue;
        }

        if (rule_buff[u] == ';') //The rule processor ignores space characters (treats them as blank so just skip them)
        {
            if (rand_mode !=1)
            {
                return 0;
            }
            rand_mode = !rand_mode;
            continue;
        }

        //Check the rule gates
        if (rule_buff[u] == RULE_GATE)
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {
                return 0;
            }
            if (rule_buff[u+1] == RULE_GATE_LENGTH_EQUAL)
            {
                if (validMap[rule_buff[u+2]] == 0) //Check if the position issued for this rule is valid
                {
                    return 0;
                }
            }
            else if ( rule_buff[u+1] == RULE_GATE_STARTING_CSET || rule_buff[u+1] == RULE_GATE_ENDING_CSET)
            {
                skip++;
                if (rule_len-(u+1) < 3)
                {
                    return 0;
                }
                if (rule_buff[u+2] == 0 || validMap[rule_buff[u+2]] == 0)
                {
                    return 0;
                }
                if (rule_buff[u+3] != 117 && rule_buff[u+3] != 100 && rule_buff[u+3] != 108 && rule_buff[u+3] != 115)
                {
                    return 0;
                }
            }
            else
            {
                return 0;
            }
        }
        //End rule gates


        else if ( rule_buff[u] == RULE_OP_MANGLE_EXTRACT_MEMORY)
        {
            skip = 3;
            if (rule_len-(u+1) < 3)
            {
                return 0;
            }
            int val = rule_buff[u+1] - '0';
            if (val == 0 || validMap[rule_buff[u+1]] == 0)
            {

                return 0;
            }
            if (validMap[rule_buff[u+2]] == 0 || validMap[rule_buff[u+3]] == 0)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_OP_REPLACE_SINGLE_POS)
        {
            skip = 3;
            if (rule_len-(u+1) < 3)
            {
                return 0;
            }
            int val = rule_buff[u+1] - '0';
            if (val == 0 || validMap[rule_buff[u+1]] == 0)
            {
                puts("failed");
                return 0;
            }

        }
        else if (rule_buff[u] == RULE_OP_REPLACE_SINGLE_POS_DUAL)
        {
            skip = 4;
            if (rule_len-(u+1) < 4)
            {
                return 0;
            }
            int val = rule_buff[u+1] - '0';
            if (val == 0 || validMap[rule_buff[u+1]] == 0)
            {
                    return 0;
            }

        }
        else if ( rule_buff[u] == RULE_MEM_COPY_BLOCK || rule_buff[u] == RULE_MEM_CUT_BLOCK)
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                    return 0;
            }
            int val = rule_buff[u+2] - '0';
            if (val == 0 || validMap[rule_buff[u+2]] == 0)
            {
                    return 0;
            }
        }
        else if ( rule_buff[u] == RULE_OP_MANGLE_EXTRACT)
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }
            int val = rule_buff[u+2] - '0';
            if (val == 0 || validMap[rule_buff[u+2]] == 0)
            {
                return 0;
            }
        }

        else if (rule_buff[u] == RULE_IF || rule_buff[u] == RULE_WHILE) //Special rules
        {
            if (remSpace(rule_buff,u) != 0)
            {
                u--;
                rule_len--;
                continue;
            }
            if (isLogical[rule_buff[u+1]] == 0)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_MEM_INSERT  || rule_buff[u] == RULE_MEM_OVERWRITE || rule_buff[u] == RULE_OP_MANGLE_TOGGLE_AT || rule_buff[u] == RULE_OP_MANGLE_DELETE_AT)
        {
            skip = 1;
            if (rule_len-(u+1) < 1)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }

        }
        else if (rule_buff[u] == RULE_OP_MANGLE_DUPEWORD_TIMES
            || rule_buff[u] == RULE_OP_MANGLE_TRUNCATE_AT || rule_buff[u] == RULE_OP_CLONEBACKWARD || rule_buff[u] == RULE_OP_CLONEFORWARD
            || rule_buff[u] == RULE_OP_ASCIIUP || rule_buff[u] == RULE_OP_ASCIIDOWN || rule_buff[u] == RULE_OP_CLONEBLOCKF || rule_buff[u] == RULE_OP_CLONEBLOCKR
            || rule_buff[u] == RULE_GATE_LESS || rule_buff[u] == RULE_GATE_GREATER )
        {
            skip = 1;
            if (rule_len-(u+1) < 1)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }

            if (rule_buff[u] == RULE_OP_CLONEBACKWARD) //Cannot be 0 since we can't go backwards
            {
                if (rule_buff[u+1] == 0)
                {
                    return 0;
                }
            }
        }
        else if( rule_buff[u] == RULE_OP_MANGLE_INSERT  || rule_buff[u] == RULE_OP_MANGLE_OVERSTRIKE || rule_buff[u] == RULE_GATE_EQUALSCHAR_AT )
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_OP_MANGLE_DUPECHAR_FIRST || rule_buff[u] == RULE_OP_MANGLE_DUPECHAR_LAST)
        {
            skip = 1;
            if (rule_len-(u+1) < 1)
            {
                return 0;
            }
            int val = rule_buff[u+1] - '0';
            if (val == 0 || validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_OP_MANGLE_REPLACE || rule_buff[u] == RULE_OP_REPLACE_SINGLE_LEFT  || rule_buff[u] == RULE_OP_REPLACE_SINGLE_RIGHT)
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {
                return 0;
            }
            if (rule_buff[u+1] - rule_buff[u+2]==0)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_OP_MANGLE_APPEND || rule_buff[u] == RULE_OP_MANGLE_PREPEND || rule_buff[u] == RULE_OP_MANGLE_PURGECHAR
                 || rule_buff[u] == RULE_GATE_FIRSTCHAR || rule_buff[u] == RULE_GATE_LASTCHAR || rule_buff[u] == RULE_GATE_CONTAIN
                 || rule_buff[u] == RULE_GATE_NOT_CONTAIN)
        {
            skip = 1;
            if (rule_len-(u+1) < 1)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_OP_SWAPCHARS)
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {

                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {

                return 0;
            }

            if (validMap[rule_buff[u+2]] == 0)
            {

                return 0;
            }

        }
        else if (rule_buff[u] == RULE_OP_MANGLE_NOOP || rule_buff[u] == RULE_OP_MANGLE_LREST || rule_buff[u] == RULE_OP_MANGLE_UREST
                 || rule_buff[u] == RULE_OP_MANGLE_LREST_UFIRST || rule_buff[u] == RULE_OP_MANGLE_UREST_LFIRST
                 ||rule_buff[u] == RULE_OP_MANGLE_TREST || rule_buff[u] == RULE_OP_MANGLE_REVERSE
                 || rule_buff[u] == RULE_OP_MANGLE_DUPEWORD || rule_buff[u] == RULE_OP_MANGLE_REFLECT
                 || rule_buff[u] == RULE_OP_MANGLE_ROTATE_LEFT || rule_buff[u] == RULE_OP_MANGLE_ROTATE_RIGHT
                 || rule_buff[u] == RULE_OP_MANGLE_DELETE_FIRST || rule_buff[u] == RULE_OP_MANGLE_DELETE_LAST
                 || rule_buff[u] == RULE_OP_MANGLE_EXTRACT_MEMORY || rule_buff[u] == RULE_OP_MANGLE_APPEND_MEMORY
                 || rule_buff[u] == RULE_OP_MANGLE_PREPEND_MEMORY || rule_buff[u] ==  RULE_OP_MEMORIZE
                 || rule_buff[u] == RULE_OP_SWAPFRONT || rule_buff[u] == RULE_OP_SWAPBACK || rule_buff[u] == RULE_GATE_MEM_CONTAINS
                 || rule_buff[u] == RULE_OP_TITLE)
                {}
        else if ( rule_buff[u] == RULE_MEM_TOGGLE)
        {
            mem_mode = !mem_mode;
        }
        else //If nothing matched then fail the verification
        {
            return 0;
        }
    }

    if (mem_mode  == 1 || rand_mode == 1) //Ensure the user actually untoggled the mem_editor or closed the random function
    {
        return 0;
    }

    return 1;
}

void initMaps()
{
    int i = 0;
        //Map the logical operators
    for (i = 0; i<sizeof(logicOPs); i++)
    {
        isLogical[logicOPs[i]] = 1; //Mark the logical Operators
    }
    //End map logical operators

    //Map the rule operations

    for (i = 0; i<sizeof(singleR); i++)
    {
        RuleOPs[singleR[i]] = 1; //Single
    }
    for (i = 0; i<sizeof(DoubleR); i++)
    {
        RuleOPs[DoubleR[i]] = 2; //Double
    }
    for (i = 0; i<sizeof(TripleR); i++)
    {
        RuleOPs[TripleR[i]] = 3; //Triple
    }
    for (i = 0; i<sizeof(QuadR); i++)
    {
        RuleOPs[QuadR[i]] = 4; //Quad
    }
    //End Mapping Operations

    for (i = 0; i<62; i++)
    {
        posMap[mapstring[i]] = i;
    }

    for (i = 0; i<sizeof(lower)-1; i++)
    {
        charMap[lower[i]] = 108;
    }
    for (i = 0; i<sizeof(upper)-1; i++)
    {
        charMap[upper[i]] = 117;
    }
    for (i = 0; i<sizeof(numbers)-1; i++)
    {
        charMap[numbers[i]] = 100;
    }
    for (i = 0; i<sizeof(symbols)-1; i++)
    {
        charMap[symbols[i]] = 115;
    }

    //Initialize the full map
    for (i = 0; i<BUFSIZ;i++)
    {
        toggleMap[i] = i;
    }
    //Map the reverse toggles
    for (i = 0; i< sizeof(lower) ;i++)
    {
        toggleMap[lower[i]] = upper[i];
        toggleMap[upper[i]] = lower[i];
    }
    for (i = 0; i<sizeof(uspecial); i++)
    {
        toggleMap[uspecial[i]] = lspecial[i];
        toggleMap[lspecial[i]] = uspecial[i];
    }
}

int skipCalc(char** RuleMap, int ruleNum, int offset)
{
    int calc = 0;
    while (1)
        {
            if (RuleMap[ruleNum][offset]==34) break;
            calc+= RuleOPs[RuleMap[ruleNum][offset]];
            offset += RuleOPs[RuleMap[ruleNum][offset]];
        }
    return calc;
}

int markRules(char** RuleMap, int ruleNum, int offset)
{
    int qt_counter = 0;
    int qt_flag = 0;
    int initial_offset = offset; //Holds the value we started at so we can calculate the actual offset rather than the position
    while (1)
        {
            if (RuleMap[ruleNum][offset]==59)
            {
                LongJump = offset;
                break;
            }
            if (RuleMap[ruleNum][offset]==34)
            {

                qt_flag = !qt_flag;
                if (qt_flag)
                {
                    qt_counter ++;
                    RuleJump[qt_counter] = (offset-initial_offset)+2;
                }
                else
                {
                    offset ++;
                    continue;
                }

            }
            offset += RuleOPs[RuleMap[ruleNum][offset]];
        }
    return qt_counter;
}


int main(int argc, char *argv[])
{


if (argc == 1)
    {
        fprintf (stderr,"\nRulify - A Rule Processor, part of the Unified List Manager (ULM) project unifiedlm.com\n\n");
        fprintf (stderr,"usage: %s -i infile -r rulefile [options]\n\nOptions:\n\t-v\tVerify rules (Shows valid/invalid rules)\n",argv[0]);
        return -1;
    }

        char *ivalue = NULL;
        char *rvalue = NULL;
        int index;
        int check = 0;
        int c;

       opterr = 0;

       while ((c = getopt (argc, argv, "fpvi:r:")) != -1)
         switch (c)
           {
           case 'i':
             ivalue = optarg;
             break;
           case 'r':
             rvalue = optarg;
             break;
           case 'v':
             check = 1;
             break;
           case '?':
             if (optopt == 'i' || optopt == 'r')
               fprintf (stderr, "Option -%c requires an argument.\n", optopt);
             else if (isprint (optopt))
               fprintf (stderr, "Unknown option `-%c'.\n", optopt);
             else
               fprintf (stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
             return 1;
           default:
             abort ();
           }

        for (index = optind; index < argc; index++)
        printf ("Non-option argument %s\n", argv[index]);


    if (ivalue== NULL  || rvalue == NULL)
    {
        printf("Please specify input -i input file, -r rule file parameters\n");
        return -1;
    }

    char ruleFile[BUFSIZ];
    sprintf (ruleFile, "%s", rvalue);
    FILE *readStream = fopen(ruleFile, "rb");
    if (ruleFile == NULL)
    {
        printf("Error opening rule file %s\n",ruleFile);
        exit(1);
    }

    char inFile[BUFSIZ];
    sprintf (inFile, "%s", ivalue);
    FILE *inputFile = fopen(inFile, "rb");
    if (inFile == NULL)
    {
        printf("Error opening file %s\n",ruleFile);
        exit(1);
    }

    unsigned int sz = 0; //Variable to hold size of file
    fseek(readStream, 0L, SEEK_END); //Jump to EOF
    sz = ftell(readStream); //Grab the bytes
    fseek(readStream, 0L, SEEK_SET); //Reset back to start of file
    char * RuleFileBuffer = (char*) malloc(sz+1);
    fread(RuleFileBuffer, sizeof(char), sz, readStream); //This is bad practice and will lead to errors if file is too large, should allocate in chunks
    fclose(readStream);
    unsigned int readItems = 0;
    //Count where file actually starts excluding blanks
    unsigned int ActualStart = 0;
    unsigned int i = 0;
    for ( i = 0; i< sz; i++)
    {
        if ((int)RuleFileBuffer[i] != 10 && (int)RuleFileBuffer[i] != 13 && (int)RuleFileBuffer[i] != 0)
        {
            ActualStart = i;
            break;
        }
    }
    //Count where we actually need to end excluding trailing blank lines
    unsigned int ActualEnd = 0;
    for (i = sz; i> 0; i--)
    {
        if ((int)RuleFileBuffer[i] != 10 && (int)RuleFileBuffer[i] != 13 && (int)RuleFileBuffer[i] != 0)
        {
            ActualEnd = sz+1;
            break;
        }
    }
    RuleFileBuffer[sz] = '\0';

    for ( i = ActualStart; i< ActualEnd; i++)
    {
        if ((int)RuleFileBuffer[i] == 10 || (int)RuleFileBuffer[i] == 13)
        {
            RuleFileBuffer[i] = '\0';
            if ((int)RuleFileBuffer[i+1] != 10 && (int)RuleFileBuffer[i+1] != 13 && (int)RuleFileBuffer[i+1] != 0)
            {
                readItems++;
            }
        }
        else if((int)RuleFileBuffer[i] == 0)
        {
            readItems++;
        }
    }


initMaps();

    char **RuleMap = (char**) malloc(readItems * sizeof(char*));
    int trigger = 1;
    unsigned int counter = 0;
    for ( i = ActualStart; i< ActualEnd ; i++)
    {

        if ((int)RuleFileBuffer[i] == 0)
        {
            trigger = 1;
        }
        else if (trigger ==1 && RuleFileBuffer[i] !=0) //Added additional gate
        {

            trigger = 0;
            if (validateRule(RuleFileBuffer+i))
            {
                RuleMap[counter] = RuleFileBuffer+i;
                counter ++;
                if (check == 1)
                {
                    printf("Validated rule:%s\n" ,RuleFileBuffer+i);
                }

            }
            else
            {
                if (check == 1)
                {
                    printf("Invalid Rule:%s\n",RuleFileBuffer+i);
                }
            }
        }
    }

    if (check == 1)
    {
        free(RuleMap);
        exit(1);
    }
    char line_buff[BUFSIZ];
    char rule_buff[BUFSIZ];
    char rule_temp[BUFSIZ];
    char rule_mem[BUFSIZ];
    char line_toggle[BUFSIZ];  //Backup for toggles

    int skip = 0;
    int len = 0;
    int skipRule = 0;


int ruleNum = 0;

char line_bkp[BUFSIZ];
char *p;
  #ifdef _WIN
  setmode (0, O_BINARY);
  #endif

long line_len = 0;
long bkp_len =0;
long mem_len =0;
char swap_char[2];

int mem_mode = 0;

while (fgets(line_buff, sizeof line_buff,inputFile) != NULL) {
    p = line_buff + strlen(line_buff) - 1;
    if (*p == '\n') *p = '\0';
    if ((p != line_buff) && (*--p == '\r')) *p = '\0';

    strcpy(line_bkp,line_buff);
    bkp_len = strlen(line_bkp);
    skip = 0;
    skipRule = 0;


    for (ruleNum =0; ruleNum < counter; ruleNum++)
    {

        strcpy(line_buff,line_bkp);
        line_len = bkp_len;
        skipRule = 0;
        skip = 0;

        mem_mode = 0;
        for (i = 0; i< strlen(RuleMap[ruleNum]); i++)
        {

            //int line_len = strlen(line_buff); //Get the new size of the string since it changes each loop
            //printf("%d\n",RuleMap[ruleNum][i]);
            //printf("SkipRule: %d\n",skipRule);
            //printf("Skip: %d\n",skip);
            line_len = strlen(line_buff);
            if (skipRule == 1)
            {
                break; //Completely skip the rule if it doesn't go through gate
            }
            if (skip !=0 )
            {
                {
                    skip--;
                }

                continue;
            }

            switch (RuleMap[ruleNum][i])
            {

                case RULE_GATE:
                {
                    skip += 2;
                    switch (RuleMap[ruleNum][i+1])
                    {

                        case RULE_GATE_LENGTH_EQUAL:
                        {
                            unsigned int val = RuleMap[ruleNum][i+2] - '0';
                            if (line_len != val)
                            {
                                skip += RuleOPs[RuleMap[ruleNum][i+3]]; //Skip the next rule and it's OPs (used for inline mode future)
                                skipRule = 1;
                                break;
                            }
                        }
                        case RULE_GATE_STARTING_CSET:
                        {
                            skip ++;

                            if (line_len < RuleMap[ruleNum][i+2] -'0')
                            {
                                break;
                            }
                            else
                            {
                                int b = 0;
                                int max = RuleMap[ruleNum][i+2]-'0';

                                for (b = 0; b< max; b++)
                                {
                                    if (charMap[line_buff[b]] != RuleMap[ruleNum][i+3])
                                    {
                                        skipRule = 1;
                                    }
                                }
                            }
                            break;
                        }
                        case RULE_GATE_ENDING_CSET:
                        {
                            skip ++;
                            if (line_len < RuleMap[ruleNum][i+2]-'0')
                            {
                                break;
                            }
                            else
                            {
                                int b = 0;
                                int max = (line_len - (RuleMap[ruleNum][i+2]-'0'));
                                for (b = line_len-1; b>= max; b--)
                                {
                                    if (charMap[line_buff[b]] != RuleMap[ruleNum][i+3])
                                    {
                                        skipRule = 1;
                                    }
                                }
                            }
                            break;
                        }
                    }
                    break;
                }

                //Hashcat Gating rules
                case RULE_GATE_LESS: //Rejects if length is greater than N
                    {
                        skip = 1;
                        unsigned int val = RuleMap[ruleNum][i+1] - '0';
                        if (line_len >= val)
                        {
                            skipRule = 1;
                        }
                        break;
                    }
                case RULE_GATE_GREATER: //Rejects if length is less than N
                    {
                        skip = 1;
                        unsigned int val = RuleMap[ruleNum][i+1] - '0';
                        if (line_len <= val)
                        {
                            skipRule = 1;
                        }
                        break;
                    }
                case RULE_GATE_CONTAIN:
                    {
                        skip = 1;
                        if (strchr(line_buff,RuleMap[ruleNum][i+1]) == NULL) //Search for the char within line_buff
                        {
                            skipRule = 1;
                        }
                        break;
                    }
                case RULE_GATE_NOT_CONTAIN:
                    {
                        skip = 1;
                        if (strchr(line_buff,RuleMap[ruleNum][i+1]) != NULL) //Search for the char within line_buff
                        {
                            skipRule = 1;
                        }
                        break;
                    }
                case RULE_GATE_LASTCHAR:
                    {
                        skip = 1;
                        if (line_buff[line_len-1] != RuleMap[ruleNum][i+1])
                        {
                             skipRule = 1;
                        }
                        break;
                    }
                case RULE_GATE_FIRSTCHAR:
                    {
                        skip= 1;
                        if (line_buff[0] != RuleMap[ruleNum][i+1])
                        {
                            skipRule = 1;
                        }
                        break;
                    }

                case RULE_GATE_EQUALSCHAR_AT: //Rejects if char at pos X != N
                    {
                        skip = 2;
                        int pos = posMap[RuleMap[ruleNum][i+1]];
                        if (line_buff[pos] != RuleMap[ruleNum][i+2])
                        {
                            skipRule = 1;
                        }
                        break;
                    }
                case RULE_GATE_MEM_CONTAINS:
                    {
                        skip = 1;

                        if (strcmp(line_buff,rule_mem) == 0)
                        {
                            skipRule = 1;
                        }
                    }
                //End hashcat gating rules

                case RULE_OP_MANGLE_TOGGLE_AT:
                {
                    skip = 1;
                    if (posMap[RuleMap[ruleNum][i+1]] > line_len)
                    {continue;}
                    int pos = 0;
                    posMap[RuleMap[ruleNum][i+1]];
                    line_buff[pos] = toggleMap[line_buff[pos]];
                    break;
                }
                case RULE_MEM_COPY_BLOCK:
                {
                    skip =2;
                    int ilen = 0;
                    int start = 0;

                    start = (RuleMap[ruleNum][i+1]-'0');
                    ilen = (RuleMap[ruleNum][i+2]-'0');

                    if (start+ilen > line_len) {continue;}
                    memcpy(rule_mem,line_buff+start,ilen);
                    rule_mem[ilen] = 0;
                    break;
                }
                case RULE_MEM_CUT_BLOCK:
                {
                    skip =2;
                    int ilen = 0;
                    int start = 0;

                    start = (RuleMap[ruleNum][i+1]-'0');
                    ilen = (RuleMap[ruleNum][i+2]-'0');

                    if (start+ilen > line_len) {continue;}
                    memcpy(rule_mem,line_buff+start,ilen);
                    rule_mem[ilen] = 0;
                    strcpy(line_buff+start,line_buff+start+ilen);
                    break;
                }
                case RULE_MEM_INSERT:
                {
                    skip = 1;
                    if (posMap[RuleMap[ruleNum][i+1]] > line_len)
                    {continue;}
                    strcpy(rule_temp,line_buff);
                    int randVal = 0;
                    randVal =  posMap[RuleMap[ruleNum][i+1]];

                    strcpy(line_buff+randVal,rule_mem);
                    strcpy(line_buff+randVal+strlen(rule_mem),rule_temp+randVal);
                    break;
                }
                case RULE_MEM_OVERWRITE:
                {
                    skip = 1;
                    if ( posMap[RuleMap[ruleNum][i+1]] > line_len)
                    {continue;}
                    strcpy(rule_temp,line_buff);
                    int randVal = 0;
                    randVal = posMap[RuleMap[ruleNum][i+1]];

                    strcpy(line_buff+randVal,rule_mem);
                    break;
                }
                case RULE_OP_MANGLE_TREST:
                {
                    int b = 0;
                    for (b= 0; b<line_len; b++)
                    {
                        line_buff[b] = toggleMap[line_buff[b] ];
                    }
                    break;
                }

                case RULE_OP_MANGLE_REPLACE:
                {
                    skip = 2;
                    char match = RuleMap[ruleNum][i+1];
                    char write = RuleMap[ruleNum][i+2];
                    int b = 0;

                    for (b = 0;b<line_len; b++)
                    {
                        if (line_buff[b] == match)
                        {
                            line_buff[b] = write;
                        }
                    }
                    break;
                }
                case RULE_OP_REPLACE_SINGLE_POS_DUAL:
                {
                    skip = 4;
                    char match = RuleMap[ruleNum][i+2];
                    char write1 = RuleMap[ruleNum][i+3];
                    char write2 = RuleMap[ruleNum][i+4];
                    int b = 0;
                    int instance = 0;
                    int needinstance;
                    needinstance = RuleMap[ruleNum][i+1]-'0';


                    for (b = 0;b<line_len; b++)
                    {
                        if (line_buff[b] == match)
                        {
                            instance ++;
                            if (instance == needinstance)
                            {
                                strcpy(rule_temp,line_buff);
                                strcpy(line_buff+b+1, rule_temp+b);
                                line_buff[b] = write1;
                                line_buff[b+1] = write2;
                                break;
                            }
                        }
                    }
                    break;
                }
                case RULE_OP_REPLACE_SINGLE_POS:
                {
                    skip = 3;
                    char match = RuleMap[ruleNum][i+2];
                    char write = RuleMap[ruleNum][i+3];
                    int b = 0;
                    int instance = 0;
                    int needinstance;
                    needinstance =  RuleMap[ruleNum][i+1]-'0';

                    for (b = 0;b<line_len; b++)
                    {
                        if (line_buff[b] == match)
                        {
                            instance ++;
                            if (instance == needinstance)
                            {
                                line_buff[b] = write;
                                break;
                            }
                        }
                    }
                    break;
                }
                case RULE_OP_REPLACE_SINGLE_LEFT:
                {
                    skip = 2;
                    char match = 0;
                    char write = 0;
                    match = RuleMap[ruleNum][i+1];
                    write = RuleMap[ruleNum][i+2];

                    int b = 0;

                    for (b = 0;b<line_len; b++)
                    {
                        if (line_buff[b] == match)
                        {
                            line_buff[b] = write;
                            break;
                        }
                    }
                    break;
                }
                case RULE_OP_REPLACE_SINGLE_RIGHT:
                {
                    skip = 2;
                    char match = 0;
                    char write = 0;
                    match = RuleMap[ruleNum][i+1];
                    write = RuleMap[ruleNum][i+2];

                    int b = 0;
                    for (b = line_len-1;b>-1; b--)
                    {
                        if (line_buff[b] == match)
                        {
                            line_buff[b] = write;
                            break;
                        }
                    }
                    break;
                }
                case RULE_OP_MANGLE_EXTRACT:
                {
                    skip =2;
                    int ilen = RuleMap[ruleNum][i+2]-'0';
                    int start = RuleMap[ruleNum][i+1]-'0';
                    if (start+ilen > line_len) {continue;}
                    strcpy(line_buff+start,line_buff+start+ilen);
                    line_len -= ilen;
                    break;
                }

                case RULE_OP_MANGLE_PURGECHAR:
                {
                    skip =1;
                    strcpy(rule_temp,line_buff);
                    int b = 0;
                    char needle = RuleMap[ruleNum][i+1];
                    int count = 0; //Stores the new shortened value offset
                    len = strlen(rule_temp);

                    for (b = 0;b<len;b++)
                    {
                        if (rule_temp[b] == needle)
                        {
                            strcpy(line_buff+b-count,rule_temp+b+1);
                            count++;
                        }
                    }
                    line_len -= count;
                    break;
                }

                case RULE_OP_MANGLE_DUPECHAR_ALL:
                {
                    strcpy(rule_temp,line_buff);
                    int b = 1;
                    int count = 0;

                    for (b = 1; b<=2*line_len; b+=2)
                    {
                        strcpy(line_buff+b,rule_temp+count);
                        count++;
                    }
                    line_len = line_len * 2;
                    break;
                }
                case RULE_OP_MANGLE_EXTRACT_MEMORY:
                {
                    skip = 3;
                    strcpy(rule_temp,line_buff);
                    int pos = RuleMap[ruleNum][i+3] - '0';
                    int ilen = RuleMap[ruleNum][i+2] - '0';
                    int start = RuleMap[ruleNum][i+1] - '0';

                    if (pos > line_len) {continue;}
                    if (start + ilen >strlen(rule_mem)) {continue;}

                    strcpy(line_buff+pos+ilen,rule_temp+pos);
                    memcpy(line_buff+pos,rule_mem+start,ilen);
                    line_len += ilen;
                    break;
                }

                case RULE_OP_MANGLE_APPEND_MEMORY:
                {
                    strcpy(line_buff+strlen(line_buff),rule_mem);
                    line_len += mem_len;
                    break;
                }

                case RULE_OP_MANGLE_PREPEND_MEMORY:
                {
                    strcpy(rule_buff,line_buff);
                    strcpy(line_buff+strlen(rule_mem),rule_buff);
                    memcpy(line_buff,rule_mem,strlen(rule_mem));
                    line_len += mem_len;
                    break;
                }

                case RULE_OP_MEMORIZE:
                {
                    strcpy(rule_mem,line_buff);
                    mem_len = line_len;
                    break;
                }

                case RULE_OP_MANGLE_ROTATE_LEFT:
                {
                    if (line_len <1) {continue;}
                    strcpy(rule_temp,line_buff);
                    strcpy(line_buff,rule_temp+1);
                    memcpy(line_buff+line_len-1,rule_temp,1);
                    break;
                }

                case RULE_OP_MANGLE_ROTATE_RIGHT:
                {
                    if (line_len <1) {continue;}
                    strcpy(rule_temp,line_buff);
                    memcpy(line_buff+1,rule_temp,strlen(line_buff)-1);
                    memcpy(line_buff,rule_temp+strlen(line_buff)-1,1);
                    break;
                }

                case RULE_OP_MANGLE_PREPEND:
                {
                    skip = 1;
                    strcpy(rule_temp, line_buff);
                    strcpy(line_buff+1, rule_temp);
                    memcpy(line_buff,RuleMap[ruleNum]+i+1,1);
                    line_len ++;
                    break;
                }

                case RULE_OP_MANGLE_APPEND:
                {
                    skip = 1;
                    memcpy(line_buff+line_len,RuleMap[ruleNum]+i+1,1);
                    memcpy(line_buff+line_len+1,"\0",1);
                    line_len ++;
                    break;
                }
                case RULE_OP_MANGLE_LREST:
                {
                    int b = 0;
                    for (b = 0; b<line_len; b++)
                    {
                        line_buff[b] = tolower(line_buff[b]);
                    }
                    break;
                }
                case RULE_OP_MANGLE_UREST:
                {
                    int b = 0;
                    for (b = 0; b<line_len; b++)
                    {
                        line_buff[b] = toupper(line_buff[b]);
                    }
                    break;
                }
                case RULE_OP_TITLE:
                {
                    int b = 0;
                    line_buff[0] = toupper(line_buff[0]);
                    for (b = 1; b<line_len; b++)
                    {
                        if (line_buff[b-1]== 32)
                        {
                            line_buff[b] = toupper(line_buff[b]);
                        }
                        else
                        {
                            line_buff[b] = tolower(line_buff[b]);
                        }

                    }
                    break;
                }
                case RULE_OP_MANGLE_LREST_UFIRST:
                {
                    int b = 0;
                    line_buff[0] = toupper(line_buff[0]);
                    for (b = 1; b<line_len; b++)
                    {
                        line_buff[b] = tolower(line_buff[b]);
                    }
                    break;
                }
                case RULE_OP_MANGLE_UREST_LFIRST:
                {
                    int b = 0;
                    line_buff[0] =  tolower(line_buff[0]);
                    for (b = 1; b<line_len; b++)
                    {
                        line_buff[b] = toupper(line_buff[b]);
                    }
                    break;
                }
                case RULE_OP_MANGLE_DELETE_FIRST:
                {
                    strcpy(line_buff, line_buff+1);
                    line_len --;
                    break;
                }
                case RULE_OP_MANGLE_REFLECT:
                {
                    int b = 0;
                    int c = line_len;
                    for (b = (line_len-1); b>=0; b--)
                    {
                        memcpy(line_buff+c, line_buff+b,1);
                        c++;
                    }
                    memcpy(line_buff+c,"\0",1);
                    line_len = line_len *2;
                    break;
                }
                case RULE_OP_MANGLE_DELETE_LAST:
                {
                    memcpy(line_buff+strlen(line_buff)-1,"\0",1);
                    line_len --;
                    break;
                }
                case RULE_OP_MANGLE_INSERT:
                {
                    skip = 2;

                    if (posMap[RuleMap[ruleNum][i+1]] > line_len)
                        {continue;}

                    strcpy(rule_temp,line_buff);
                    int RandVal = 0;

                    RandVal = posMap[RuleMap[ruleNum][i+1]];
                    strcpy(line_buff+posMap[RuleMap[ruleNum][i+1]]+1, rule_temp+posMap[RuleMap[ruleNum][i+1]]);
                    memcpy(line_buff+RandVal,RuleMap[ruleNum]+i+2,1);


                    break;
                }
                case RULE_OP_MANGLE_OVERSTRIKE:
                {
                    skip = 2;
                    if (RuleMap[ruleNum][i+1] != '?' && posMap[RuleMap[ruleNum][i+1]] > line_len)
                        {continue;}
                    int RandVal = 0;

                    RandVal = posMap[RuleMap[ruleNum][i+1]];
                    memcpy(line_buff+RandVal,RuleMap[ruleNum]+i+2,1);

                    break;
                }
                case RULE_OP_MANGLE_TRUNCATE_AT:
                {
                    skip = 1;
                    if (line_len > posMap[RuleMap[ruleNum][i+1]]+1)
                    {

                        line_buff[posMap[RuleMap[ruleNum][i+1]]] = '\0';
                        line_len = posMap[RuleMap[ruleNum][i+1]]+1;
                    }
                    break;
                }
                case RULE_OP_MANGLE_REVERSE:
                {
                    strcpy(rule_temp,line_buff);
                    int b = 0;
                    int c = 0;
                    for (b = line_len-1; b>=0; b--)
                    {
                        line_buff[c] = (rule_temp[b]);
                        c++;
                    }
                    break;
                }
                case RULE_OP_MANGLE_DUPEWORD:
                {
                    strcpy(rule_temp,line_buff);
                    strcpy(line_buff+strlen(line_buff),rule_temp);
                    line_len = line_len * 2;
                    break;
                }
                case RULE_OP_MANGLE_DUPEWORD_TIMES:
                {
                    skip = 1;
                    int dupes = 0;
                    strcpy(rule_temp,line_buff);
                    for (dupes = posMap[RuleMap[ruleNum][i+1]]; dupes != 0; dupes--)
                    {
                        strcpy(line_buff+strlen(line_buff),rule_temp);
                    }
                    line_len = line_len *(posMap[RuleMap[ruleNum][i+1]]+1);
                    break;
                }
                case RULE_OP_MANGLE_DELETE_AT:
                {
                    skip =1;
                    int delpos = 0;
                    delpos =  posMap[RuleMap[ruleNum][i+1]];

                    if (delpos < line_len )
                    {
                        strcpy(line_buff+delpos,line_buff+delpos+1);
                    }

                    break;
                }
                case RULE_OP_MANGLE_DUPECHAR_FIRST:
                {
                    skip = 1;
                    strcpy(rule_temp,line_buff);
                    int reps = RuleMap[ruleNum][i+1] - '0';
                    strcpy(line_buff+reps,rule_temp);
                    int b = 0;
                    for (b = 0;b<reps;b++)
                    {
                        line_buff[b] = rule_temp[0];
                    }
                    line_len =+ reps;
                    break;
                }
                case RULE_OP_MANGLE_DUPECHAR_LAST:
                {
                    skip = 1;
                    int reps = RuleMap[ruleNum][i+1] - '0';
                    int b = 0;

                    for (b = 0; b<reps; b++)
                    {
                        line_buff[line_len+b] = line_buff[line_len-1];
                    }
                    line_buff[line_len+reps] = 0;
                    line_len =+ reps;
                    break;
                }
                case RULE_OP_SWAPFRONT:
                {
                    if (line_len > 1)
                    {
                        memcpy(swap_char,line_buff+1,1);
                        memcpy(line_buff+1,line_buff,1);
                        memcpy(line_buff,swap_char,1);
                    }
                    break;
                }
                case RULE_OP_SWAPBACK:
                {
                    if (line_len > 2)
                    {
                        memcpy(swap_char,line_buff+(line_len-1),1);
                        memcpy(line_buff+(line_len-1),line_buff+(line_len-2),1);
                        memcpy(line_buff+(line_len-2),swap_char,1);
                    }
                    break;
                }
                case RULE_OP_SWAPCHARS:
                {
                    skip =2;
                    int num1 = 0;
                    int num2 = 0;
                    num1 = posMap[RuleMap[ruleNum][i+1]];
                    num2 = posMap[RuleMap[ruleNum][i+2]];

                    if (line_len > num1 && line_len > num2)
                    {
                        memcpy(swap_char,line_buff+num1,1);
                        memcpy(line_buff+num1,line_buff+num2,1);
                        memcpy(line_buff+num2,swap_char,1);
                    }

                    break;
                }
                case RULE_OP_CLONEBACKWARD:
                {
                    skip = 1;
                    if (line_len > posMap[RuleMap[ruleNum][i+1]])
                    {
                        memcpy(line_buff+posMap[RuleMap[ruleNum][i+1]],line_buff+posMap[RuleMap[ruleNum][i+1]]-1,1);
                    }
                    break;
                }
                case RULE_OP_CLONEFORWARD:
                {
                    skip = 1;
                    if (line_len > posMap[RuleMap[ruleNum][i+1]]+1)
                    {
                        memcpy(line_buff+(int)posMap[RuleMap[ruleNum][i+1]],line_buff+(int)posMap[RuleMap[ruleNum][i+1]]+1,1);
                    }
                    break;
                }
                case RULE_OP_ASCIIUP:
                {
                    skip = 1;
                    if (line_len > posMap[RuleMap[ruleNum][i+1]])
                    {
                        line_buff[posMap[RuleMap[ruleNum][i+1]]] = line_buff[posMap[RuleMap[ruleNum][i+1]]]+1;
                    }
                    break;
                }
                case RULE_OP_ASCIIDOWN:
                {
                    skip = 1;
                    if (line_len > posMap[RuleMap[ruleNum][i+1]])
                    {
                        line_buff[posMap[RuleMap[ruleNum][i+1]]] = line_buff[posMap[RuleMap[ruleNum][i+1]]]-1;
                    }
                    break;
                }
                case RULE_OP_CLONEBLOCKF:
                {
                    skip = 1;
                    if (line_len >= posMap[RuleMap[ruleNum][i+1]])
                    {
                        strcpy(rule_buff,line_buff);
                        //strcpy(line_buff+line_len,rule_buff+(line_len-posMap[RuleMap[ruleNum][i+1]]));
                        strcpy(line_buff+posMap[RuleMap[ruleNum][i+1]],rule_buff);
                        memcpy(line_buff,rule_buff,posMap[RuleMap[ruleNum][i+1]]);
                    }
                    break;
                }
                case RULE_OP_CLONEBLOCKR:
                {
                    skip = 1;
                    if (line_len >=posMap[RuleMap[ruleNum][i+1]])
                    {
                        strcpy(rule_buff,line_buff);
                        strcpy(line_buff+line_len,rule_buff+(line_len-posMap[RuleMap[ruleNum][i+1]]));
                        //strcpy(line_buff+(posMap[RuleMap[ruleNum][i+1]]*2),rule_buff+posMap[RuleMap[ruleNum][i+1]]);
                        //memcpy(line_buff+posMap[RuleMap[ruleNum][i+1]],rule_buff,posMap[RuleMap[ruleNum][i+1]]);
                    }
                    break;
                }
                case RULE_MEM_TOGGLE:
                {
                    if (mem_mode == 0)
                    {
                        strcpy(line_toggle,line_buff);
                        strcpy(line_buff,rule_mem);
                        strcpy(line_buff,rule_mem);
                        mem_mode = 1;
                    }
                    else
                    {
                        strcpy(rule_mem,line_buff);
                        strcpy(line_buff,line_toggle);
                        mem_mode = 0;
                    }
                    break;
                }
            }
        }

        if (skipRule == 0)
        {
            puts(line_buff);
        }
    }
}
    return 0;
}
