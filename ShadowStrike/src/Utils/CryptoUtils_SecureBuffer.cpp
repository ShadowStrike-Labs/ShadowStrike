// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#include"pch.h"
#include"CryptoUtils.hpp"
#include"CryptoUtilsCommon.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace CryptoUtils {

			// =============================================================================
			// SecureBuffer Implementation
			// =============================================================================
			template<typename T>
			SecureBuffer<T>::SecureBuffer(size_t size) : m_size(0) {
				if (size > 0) allocate(size);
			}

			template<typename T>
			SecureBuffer<T>::~SecureBuffer() {
				deallocate();
			}

			template<typename T>
			SecureBuffer<T>::SecureBuffer(SecureBuffer&& other) noexcept
				: m_data(other.m_data), m_size(other.m_size)
			{
				other.m_data = nullptr;
				other.m_size = 0;
			}

			template<typename T>
			SecureBuffer<T>& SecureBuffer<T>::operator=(SecureBuffer&& other) noexcept {
				if (this != &other) {
					deallocate();
					m_data = other.m_data;
					m_size = other.m_size;
					other.m_data = nullptr;
					other.m_size = 0;
				}
				return *this;
			}

			template<typename T>
			void SecureBuffer<T>::Resize(size_t newSize) {
				if (newSize == m_size) return;
				deallocate();
				if (newSize > 0) allocate(newSize);
			}

			template<typename T>
			void SecureBuffer<T>::Clear() {
				deallocate();
			}

			template<typename T>
			void SecureBuffer<T>::CopyFrom(const T* src, size_t count) {
				Resize(count);
				if (count > 0 && m_data && src) {
					std::memcpy(m_data, src, count * sizeof(T));
				}
			}

			template<typename T>
			void SecureBuffer<T>::CopyFrom(const std::vector<T>& src) {
				CopyFrom(src.data(), src.size());
			}

			template<typename T>
			void SecureBuffer<T>::allocate(size_t size) {
#ifdef _WIN32
				m_data = static_cast<T*>(VirtualAlloc(nullptr, size * sizeof(T), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
				if (m_data) {
					m_size = size;
					VirtualLock(m_data, m_size * sizeof(T));
				}
#else
				m_data = static_cast<T*>(std::malloc(size * sizeof(T)));
				if (m_data) m_size = size;
#endif
			}

			template<typename T>
			void SecureBuffer<T>::deallocate() {
				if (m_data) {
					SecureZeroMemory(m_data, m_size * sizeof(T));
#ifdef _WIN32
					VirtualUnlock(m_data, m_size * sizeof(T));
					VirtualFree(m_data, 0, MEM_RELEASE);
#else
					std::free(m_data);
#endif
					m_data = nullptr;
					m_size = 0;
				}
			}

			// Explicit instantiation
			template class SecureBuffer<uint8_t>;
			template class SecureBuffer<char>;
			template class SecureBuffer<wchar_t>;

			// =============================================================================
			// SecureString Implementation	
			// =============================================================================
			SecureString::SecureString(std::string_view str) {
				Assign(str);
			}

			SecureString::SecureString(std::wstring_view str) {
				Assign(str);
			}

			SecureString::~SecureString() {
				Clear();
			}

			SecureString::SecureString(SecureString&& other) noexcept
				: m_buffer(std::move(other.m_buffer))
			{
			}

			SecureString& SecureString::operator=(SecureString&& other) noexcept {
				if (this != &other) {
					m_buffer = std::move(other.m_buffer);
				}
				return *this;
			}

			void SecureString::Assign(std::string_view str) {
				m_buffer.CopyFrom(str.data(), str.size() + 1);
			}

			void SecureString::Assign(std::wstring_view str) {
				// UTF-16 → UTF-8 conversion using Windows API
				if (str.empty()) {
					Clear();
					return;
				}

				int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
					nullptr, 0, nullptr, nullptr);
				if (sizeNeeded <= 0) {
					Clear();
					return;
				}

				std::string narrow(sizeNeeded, '\0');
				WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
					&narrow[0], sizeNeeded, nullptr, nullptr);

				// Copy to secure buffer
				Assign(narrow);

				// SECURITY: Securely clear the temporary string
				SecureZeroMemory(narrow.data(), narrow.size());
			}

			void SecureString::Clear() {
				m_buffer.Clear();
			}

			std::string_view SecureString::ToStringView() const noexcept {
				if (m_buffer.Empty()) return std::string_view();
				return std::string_view(m_buffer.Data(), m_buffer.Size() > 0 ? m_buffer.Size() - 1 : 0);
			}


		}//namespace CryptoUtils
	}// namespace Utils
}// namespace ShadowStrike