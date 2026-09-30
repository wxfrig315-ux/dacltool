#include "table.h"

std::vector<std::wstring> split_into_words(const std::wstring& str)
{
    std::vector<std::wstring> words;
    std::wstring word;
    for (wchar_t c : str)
    {
        if (c == L' ')
        {
            if (!word.empty())
            {
                words.push_back(word);
                word.clear();
            }


        }
        else
        {
            word += c;
        }
    }
    if (!word.empty())
    {
        words.push_back(word);
    }
    return words;
}

std::vector<std::wstring> wrap_text(const std::wstring& text, size_t width)

{
    std::vector<std::wstring> wrapped_lines;
    std::vector<std::wstring> words = split_into_words(text);
    std::wstring line;

    for (const auto& word : words)
    {
        if (line.length() + word.length() + (line.empty() ? 0 : 1) > width)
        {
            wrapped_lines.push_back(line);
            line = word;
        }
        else
        {
            if (!line.empty())
            {
                line += L" ";
            }
            line += word;
        }
    }
    // final line we can get
    if (!line.empty())
    {
        wrapped_lines.push_back(line);
    }

    return wrapped_lines;
}

std::wstringstream generate_table(const std::vector<std::vector<std::wstring>>& table, const std::vector<size_t>& col_widths)
{
    std::wstringstream ss;

    if (table.empty() || col_widths.empty())
    {
        return ss;
    }

    size_t num_cols = col_widths.size();

    // Find the maximum number of lines needed for each row after wrapping
    //size_t max_row_lines = 1;
    std::vector<std::vector<std::vector<std::wstring>>> wrapped_table;
    std::vector<size_t> max_row_lines;
    for (const std::vector<std::wstring>& row : table)
    {
        std::vector<std::vector<std::wstring>> wrapped_row;
        size_t row_max_lines = 1;
        for (size_t col = 0; col < num_cols; ++col)
        {
            std::vector<std::wstring> wrapped_text = wrap_text(row[col], col_widths[col]);
            wrapped_row.push_back(wrapped_text);
            row_max_lines = max(row_max_lines, wrapped_text.size());
        }
        wrapped_table.push_back(wrapped_row);
        max_row_lines.push_back(row_max_lines);
    }

    // Print top border
    ss << L"+";
    for (size_t col = 0; col < num_cols; ++col)
    {
        ss << std::wstring(col_widths[col] + 2, L'-') << L"+";
    }
    ss << L"\n";

    // Print each row
    for (size_t row_idx = 0; row_idx < table.size(); ++row_idx)
    {
        // Print each line of the row
        for (size_t line = 0; line < max_row_lines[row_idx]; ++line)
        {
            ss << L"|";
            for (size_t col = 0; col < num_cols; ++col)
            {
                std::wstring cell_text = L"";
                const std::vector < std::wstring> wrapped_text = wrapped_table[row_idx][col];
                if (line < wrapped_text.size())
                {
                    cell_text = wrapped_text[line];
                }

                ss << L" " << std::left << std::setw(col_widths[col]) << cell_text << L" |";
            }
            ss << L"\n";
        }

        // Print row separator
        ss << L"+";
        for (size_t col = 0; col < num_cols; ++col)
        {
            ss << std::wstring(col_widths[col] + 2, L'-') << L"+";
        }
        ss << L"\n";
    }

    return ss;
}
